package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// listSecurityGroups returns all security groups for the specified VPC.
func listSecurityGroups(ctx context.Context, client *ec2.Client, vpcID string, verbose bool) ([]types.SecurityGroup, error) {
	if verbose {
		fmt.Printf("Fetching security groups for VPC %s.\n", vpcID)
	}

	var securityGroups []types.SecurityGroup
	for {
		filterName := "vpc-id"
		out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			Filters: []types.Filter{{
				Name:   &filterName,
				Values: []string{vpcID},
			}},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe security groups: %s", err)
		}

		securityGroups = append(securityGroups, out.SecurityGroups...)
		if out.NextToken == nil {
			break
		}
	}

	return securityGroups, nil
}

// listNetworkInterfaces returns all elastic network interfaces for the
// specified VPC.
func listNetworkInterfaces(ctx context.Context, client *ec2.Client, vpcID string, verbose bool) ([]types.NetworkInterface, error) {
	if verbose {
		fmt.Printf("Fetching elastic network interfaces for VPC %s.\n", vpcID)
	}

	var networkInterfaces []types.NetworkInterface
	for {
		filterName := "vpc-id"
		out, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters: []types.Filter{{
				Name:   &filterName,
				Values: []string{vpcID},
			}},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe network interfaces: %s", err)
		}

		networkInterfaces = append(networkInterfaces, out.NetworkInterfaces...)
		if out.NextToken == nil {
			break
		}
	}

	return networkInterfaces, nil
}

// filterSecurityGroups removes all security groups which are associated with an
// elastic network interface.
func filterSecurityGroups(securityGroups []types.SecurityGroup, networkInterfaces []types.NetworkInterface, verbose bool) [][]types.SecurityGroup {
	if verbose {
		fmt.Println("Filtering security groups.")
	}

	// Ignore the default security group and any guard duty managed security
	// groups.
	sgMap := make(map[string]types.SecurityGroup)
	for _, sg := range securityGroups {
		if *sg.GroupName != "default" && !strings.HasPrefix(*sg.GroupName, "GuardDutyManagedSecurityGroup") {
			sgMap[*sg.GroupId] = sg
		}
	}

	// Remove security groups which are associated with an elastic network
	// interface.
	for _, ni := range networkInterfaces {
		for _, group := range ni.Groups {
			groupID := *group.GroupId
			if keepSG, ok := sgMap[groupID]; ok {
				if verbose {
					fmt.Printf("Keeping security group %s (%s), associated with %s.\n", *keepSG.GroupId, *keepSG.GroupName, *ni.NetworkInterfaceId)
				}
				delete(sgMap, groupID)
			}
		}
	}

	// Remove security groups which are associated with security groups which
	// have previously been removed.
	for _, sg := range securityGroups {
		if _, ok := sgMap[*sg.GroupId]; ok {
			continue
		}

		for _, pair := range allUserIdGroupPairs(sg) {
			groupID := *pair.GroupId
			if keepSG, ok := sgMap[*pair.GroupId]; ok {
				if verbose {
					fmt.Printf("Keeping security group %s (%s), associated with %s (%s).\n", *keepSG.GroupId, *keepSG.GroupName, *sg.GroupId, *sg.GroupName)
				}
				delete(sgMap, groupID)
			}
		}
	}

	// Cluster dependant security groups together. Before being deleted, all
	// security groups in a cluster will first have their rules revoked.
	var clusters [][]types.SecurityGroup
	for _, sg := range sgMap {
		// If a security group has no dependencies on other security group, we
		// leave it in case some other security group has a dependency on it.
		pairs := allUserIdGroupPairs(sg)
		if len(pairs) == 0 {
			continue
		}

		cluster := []types.SecurityGroup{sg}
		delete(sgMap, *sg.GroupId)
		for _, pair := range pairs {
			groupID := *pair.GroupId
			if clusterSG, ok := sgMap[groupID]; ok {
				cluster = append(cluster, clusterSG)
				delete(sgMap, groupID)
			}
		}

		clusters = append(clusters, cluster)
	}
	for _, sg := range sgMap {
		clusters = append(clusters, []types.SecurityGroup{sg})
	}

	if verbose {
		for _, sgCluster := range clusters {
			var sb strings.Builder
			for _, sg := range sgCluster {
				sb.WriteString(*sg.GroupId + " (" + *sg.GroupName + "), ")
			}
			fmt.Printf("Clustering security groups %s\n", sb.String()[:sb.Len()-2])
		}

	}

	return clusters
}

// allUserIdGroupPairs returns all group pairs, both ingress and egress, for the
// specified security group.
func allUserIdGroupPairs(securityGroup types.SecurityGroup) []types.UserIdGroupPair {
	var pairs []types.UserIdGroupPair
	for _, perm := range securityGroup.IpPermissions {
		for _, pair := range perm.UserIdGroupPairs {
			pairs = append(pairs, pair)
		}
	}
	for _, perm := range securityGroup.IpPermissionsEgress {
		for _, pair := range perm.UserIdGroupPairs {
			pairs = append(pairs, pair)
		}
	}

	return pairs
}

// deleteSecurityGroups deletes the specified security groups.
func deleteSecurityGroups(ctx context.Context, client *ec2.Client, clusters [][]types.SecurityGroup, dryRun, verbose bool) error {
	if verbose {
		fmt.Println("Deleting security groups.")
	}

	for _, cluster := range clusters {
		// Revoke security group rules for security groups in the cluster.
		for _, sg := range cluster {
			if verbose {
				fmt.Printf("Revoking security group rules from %s (%s).\n", *sg.GroupId, *sg.GroupName)
			}

			// Fetch all the security group rules.
			var sgRules []types.SecurityGroupRule
			for {
				filterName := "group-id"
				out, err := client.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{
					Filters: []types.Filter{{
						Name:   &filterName,
						Values: []string{*sg.GroupId},
					}},
				})
				if err != nil {
					return fmt.Errorf("failed to fetch security group rules: %s", err)
				}

				sgRules = append(sgRules, out.SecurityGroupRules...)
				if out.NextToken == nil {
					break
				}
			}

			// Sort the rules in egress and ingress rules.
			var egressIDs, ingressIDs []string
			for _, rule := range sgRules {
				if *rule.IsEgress {
					egressIDs = append(egressIDs, *rule.SecurityGroupRuleId)
				} else {
					ingressIDs = append(ingressIDs, *rule.SecurityGroupRuleId)
				}
			}

			// Revoke all security group egress rules.
			if len(egressIDs) > 0 {
				_, err := client.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
					DryRun:               &dryRun,
					GroupId:              sg.GroupId,
					SecurityGroupRuleIds: egressIDs,
				})
				if errorOrFailedDryRun(err) {
					return fmt.Errorf("failed to revoke security group egress rules: %s", err)
				}
			}

			// Revoke all security group ingress rules.
			if len(ingressIDs) > 0 {
				_, err := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
					DryRun:               &dryRun,
					GroupId:              sg.GroupId,
					SecurityGroupRuleIds: ingressIDs,
				})
				if errorOrFailedDryRun(err) {
					return fmt.Errorf("failed to revoke security group ingress rules: %s", err)
				}
			}
		}

		// Delete security groups in the cluster.
		for _, sg := range cluster {
			if verbose {
				fmt.Printf("Deleting security group %s (%s).\n", *sg.GroupId, *sg.GroupName)
			}

			_, err := client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
				DryRun:  &dryRun,
				GroupId: sg.GroupId,
			})
			if errorOrFailedDryRun(err) {
				return fmt.Errorf("failed to delete security group: %s", err)
			}
		}
	}

	return nil
}

// errorOrFailedDryRun returns true if err is an error or a failed dry-run.
func errorOrFailedDryRun(err error) bool {
	if err != nil {
		return !strings.HasSuffix(err.Error(), "api error DryRunOperation: Request would have succeeded, but DryRun flag is set.")
	}

	return false
}

func main() {
	ctx := context.Background()

	dryRun := flag.Bool("dry-run", false, "Dry run, no resources will be modified or removed.")
	profile := flag.String("profile", "", "AWS profile, defaults to the default profile.")
	region := flag.String("region", "", "AWS region, defaults to the default region of the profile.")
	verbose := flag.Bool("verbose", false, "Enable verbose logging.")
	vpcID := flag.String("vpc-id", "", "ID of the AWS VPC to clean.")
	flag.Parse()

	if *vpcID == "" {
		fmt.Println("A VPC ID must be provided.")
		os.Exit(1)
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile), config.WithRegion(*region))
	if err != nil {
		fmt.Printf("failed to AWS configuration: %s\n", err)
		os.Exit(1)
	}

	client := ec2.NewFromConfig(awsConfig)
	securityGroups, err := listSecurityGroups(ctx, client, *vpcID, *verbose)
	if err != nil {
		fmt.Printf("failed to list security groups for vpc: %s\n", err)
		os.Exit(1)
	}
	networkInterfaces, err := listNetworkInterfaces(ctx, client, *vpcID, *verbose)
	if err != nil {
		fmt.Printf("failed to list network interfaces for vpc: %s\n", err)
		os.Exit(1)
	}

	clusters := filterSecurityGroups(securityGroups, networkInterfaces, *verbose)
	if *verbose {
		var count int
		for _, cluster := range clusters {
			count += len(cluster)
		}
		fmt.Printf("Deleting %d security groups in %d clusters.\n", count, len(clusters))
	}

	if err := deleteSecurityGroups(ctx, client, clusters, *dryRun, *verbose); err != nil {
		fmt.Printf("failed to delete security groups: %s\n", err)
		os.Exit(1)
	}
}
