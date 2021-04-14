/*
Copyright 2021 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ec2

import (
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
)

// ruleKey represents the unique tuple (protocol, from-to port) in a
// format supported as a map key
type ruleKey struct {
	protocol string // lower case
	fromPort int64  // -1 for nil
	toPort   int64  // -1 for nil
}

func getInt64Key(port *int64) int64 {
	if port == nil {
		return -1
	}
	return *port
}

func getKey(perm awsec2.IpPermission) ruleKey {
	return ruleKey{
		protocol: strings.ToLower(aws.StringValue(perm.IpProtocol)),
		fromPort: getInt64Key(perm.FromPort),
		toPort:   getInt64Key(perm.ToPort),
	}
}

func compareObjects(a, b []*string) int {
	for i := range a {
		if a[i] == nil && b[i] != nil {
			return -1
		}
		switch strings.Compare(aws.StringValue(a[i]), aws.StringValue(b[i])) {
		case -1:
			return -1
		case 1:
			return 1
		case 0:
			// continue
		}
	}
	return 0 // eq
}

func userIDGroupPairCmp(i, j awsec2.UserIdGroupPair) int {
	return compareObjects(
		[]*string{i.Description, i.GroupId, i.GroupName, i.PeeringStatus, i.UserId, i.VpcId, i.VpcPeeringConnectionId},
		[]*string{j.Description, j.GroupId, j.GroupName, j.PeeringStatus, j.UserId, j.VpcId, j.VpcPeeringConnectionId})
}

type ipPermissionMap struct {
	FromPort   *int64
	ToPort     *int64
	IPProtocol *string

	ipRanges        map[string]*string
	ipv6Ranges      map[string]*string
	prefixListIDs   map[string]*string
	userIDGroupPair []awsec2.UserIdGroupPair
}

// merge adds rules from the permission set m into this permission
// set. The caller must ensure that the permission set is for the same
// protocol and port range.
func (i *ipPermissionMap) merge(m awsec2.IpPermission) { // nolint:gocyclo
	i.FromPort = m.FromPort
	i.ToPort = m.ToPort
	i.IPProtocol = m.IpProtocol

	for _, r := range m.IpRanges {
		i.ipRanges[aws.StringValue(r.CidrIp)] = r.Description
	}

	for _, r := range m.Ipv6Ranges {
		i.ipv6Ranges[aws.StringValue(r.CidrIpv6)] = r.Description
	}

	for _, r := range m.PrefixListIds {
		i.prefixListIDs[aws.StringValue(r.PrefixListId)] = r.Description
	}

	for _, r := range m.UserIdGroupPairs {
		idx := sort.Search(len(i.userIDGroupPair), func(idx int) bool {
			return userIDGroupPairCmp(i.userIDGroupPair[idx], r) <= 0
		})

		if idx == len(i.userIDGroupPair) { // nil or after last element
			i.userIDGroupPair = append(i.userIDGroupPair, r)
		} else if userIDGroupPairCmp(i.userIDGroupPair[idx], r) != 0 {
			// not present, insert at idx
			i.userIDGroupPair = append(i.userIDGroupPair[:idx+1], i.userIDGroupPair[idx:]...) // index < len(a)
			i.userIDGroupPair[idx] = r
		}
	}
}

// diff returns rules that should be added or removed.
func (i ipPermissionMap) diff(other ipPermissionMap) (add awsec2.IpPermission, remove awsec2.IpPermission) {
	add.IpProtocol = i.IPProtocol
	add.FromPort = i.FromPort
	add.ToPort = i.ToPort
	remove = add

	add.IpRanges = i.diffRanges(other)
	remove.IpRanges = other.diffRanges(i)

	add.Ipv6Ranges = i.diffIPv6Ranges(other)
	remove.Ipv6Ranges = other.diffIPv6Ranges(i)

	add.PrefixListIds = i.diffPrefixListIDs(other)
	remove.PrefixListIds = other.diffPrefixListIDs(i)

	add.UserIdGroupPairs = i.diffUserIDGroupPair(other)
	remove.UserIdGroupPairs = other.diffUserIDGroupPair(i)

	return add, remove
}

func (i ipPermissionMap) diffRanges(other ipPermissionMap) []awsec2.IpRange {
	var ret []awsec2.IpRange
	for cidr, description := range i.ipRanges {
		cidr := cidr
		description2, ok := other.ipRanges[cidr]
		if !ok || aws.StringValue(description) != aws.StringValue(description2) {
			ret = append(ret, awsec2.IpRange{CidrIp: &cidr, Description: description})
		}
	}
	return ret
}

func (i ipPermissionMap) diffIPv6Ranges(other ipPermissionMap) []awsec2.Ipv6Range {
	var ret []awsec2.Ipv6Range
	for cidr, description := range i.ipv6Ranges {
		cidr := cidr
		description2, ok := other.ipv6Ranges[cidr]
		if !ok || aws.StringValue(description) != aws.StringValue(description2) {
			ret = append(ret, awsec2.Ipv6Range{CidrIpv6: &cidr, Description: description})
		}
	}
	return ret
}

func (i ipPermissionMap) diffPrefixListIDs(other ipPermissionMap) []awsec2.PrefixListId {
	var ret []awsec2.PrefixListId
	for id, description := range i.prefixListIDs {
		id := id
		description2, ok := other.prefixListIDs[id]
		if !ok || aws.StringValue(description) != aws.StringValue(description2) {
			ret = append(ret, awsec2.PrefixListId{PrefixListId: &id, Description: description})
		}
	}
	return ret
}

func (i ipPermissionMap) diffUserIDGroupPair(other ipPermissionMap) []awsec2.UserIdGroupPair {
	var ret []awsec2.UserIdGroupPair
	for _, r := range i.userIDGroupPair {
		idx := sort.Search(len(other.userIDGroupPair), func(idx int) bool {
			return userIDGroupPairCmp(other.userIDGroupPair[idx], r) <= 0
		})
		if idx == len(other.userIDGroupPair) || userIDGroupPairCmp(other.userIDGroupPair[idx], r) != 0 {
			ret = append(ret, r) // not found
		}
	}
	return ret
}

func convertToMaps(rules []awsec2.IpPermission) map[ruleKey]*ipPermissionMap {
	ret := make(map[ruleKey]*ipPermissionMap)

	for _, rule := range rules {
		k := getKey(rule)
		normalized, ok := ret[k]
		if !ok {
			normalized = &ipPermissionMap{}
			normalized.ipRanges = make(map[string]*string)
			normalized.ipv6Ranges = make(map[string]*string)
			normalized.prefixListIDs = make(map[string]*string)
			ret[k] = normalized
		}

		normalized.merge(rule)
	}

	return ret
}

func hasRules(perm awsec2.IpPermission) bool {
	return perm.IpRanges != nil || perm.Ipv6Ranges != nil || perm.UserIdGroupPairs != nil || perm.PrefixListIds != nil
}

func DiffPermissions(want, have []awsec2.IpPermission) (add, remove []awsec2.IpPermission) {
	// Convert the rule matrix to a map of arrays.

	// We do this to avoid O(n^2) lookup if the rule sets are large,
	// and also because the user might represent two rules
	//
	//   [(proto,port,[iprange1,iprange2])]
	// as
	//   [(proto,port,[iprange1]), (proto,port,[iprange2])]
	//
	// By converting to maps and merging rules we can get the compact
	// first form and easily check if rules are present or not.
	wantMap := convertToMaps(want)
	haveMap := convertToMaps(have)

	for key, have := range haveMap {
		want, ok := wantMap[key]
		if !ok {
			want = &ipPermissionMap{}
		}

		removeRules, addRules := have.diff(*want)

		if hasRules(addRules) {
			add = append(add, addRules)
		}

		if hasRules(removeRules) {
			remove = append(remove, removeRules)
		}
	}

	for key, want := range wantMap {
		if _, ok := haveMap[key]; !ok {
			addRules, _ := want.diff(ipPermissionMap{})
			add = append(add, addRules)
		}
	}

	return add, remove
}
