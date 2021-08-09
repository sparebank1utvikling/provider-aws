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
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/google/go-cmp/cmp"
)

var (
	port80  int64 = 80
	port100 int64 = 100

	tcpProtocol = "tcp"
)

func sgPermissions(port int64, cidrs ...string) []awsec2.IpPermission {
	ranges := make([]awsec2.IpRange, 0, len(cidrs))
	for _, cidr := range cidrs {
		ranges = append(ranges, awsec2.IpRange{
			CidrIp: aws.String(cidr),
		})
	}
	return []awsec2.IpPermission{
		{
			FromPort:   aws.Int64(port),
			ToPort:     aws.Int64(port),
			IpProtocol: aws.String(tcpProtocol),
			IpRanges:   ranges,
		},
	}
}

// NOTE(muvaf): Sending -1 as FromPort or ToPort is valid but the returned
// object does not have that value. So, in case we have sent -1, we assume
// that the returned value is also -1 in case if it's nil.
// See the following about usage of -1
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-security-group-egress.html
//mOne := int64(-1)

func TestDiffPermissions(t *testing.T) {
	type testCase struct {
		name string

		want, have  []awsec2.IpPermission
		add, remove []awsec2.IpPermission
	}

	cases := []testCase{
		{
			name:   "Same",
			want:   sgPermissions(port100, cidr),
			have:   sgPermissions(port100, cidr),
			add:    nil,
			remove: nil,
		},
		{
			name:   "Add",
			want:   sgPermissions(port100, cidr),
			have:   nil,
			add:    sgPermissions(port100, cidr),
			remove: nil,
		},
		{
			name:   "Remove",
			want:   nil,
			have:   sgPermissions(port100, cidr),
			add:    nil,
			remove: sgPermissions(port100, cidr),
		},
		{
			name:   "Replace",
			want:   sgPermissions(99, cidr),
			have:   sgPermissions(port100, cidr),
			add:    sgPermissions(99, cidr),
			remove: sgPermissions(port100, cidr),
		},
		{
			name:   "Add block",
			want:   sgPermissions(port100, cidr, "192.168.0.1/32"),
			have:   sgPermissions(port100, cidr),
			add:    sgPermissions(port100, "192.168.0.1/32"),
			remove: nil,
		},
		{
			name:   "Remove block",
			want:   sgPermissions(port100, cidr),
			have:   sgPermissions(port100, cidr, "192.168.0.1/32"),
			add:    nil,
			remove: sgPermissions(port100, "192.168.0.1/32"),
		},
		{
			name:   "Replace block",
			want:   sgPermissions(port100, cidr, "172.240.1.1/32", "192.168.0.1/32"),
			have:   sgPermissions(port100, cidr, "172.240.2.2/32", "192.168.0.1/32"),
			add:    sgPermissions(port100, "172.240.1.1/32"),
			remove: sgPermissions(port100, "172.240.2.2/32"),
		},
		/*
			{
				name:   "Dedupe want",
				want:   append(sgPersmissions(port100, cidr, "172.240.1.1/32", "172.240.1.1/32", "192.168.0.1/32"), sgPersmissions(port100, cidr, "172.240.1.1/32", "172.240.1.1/32", "192.168.0.1/32")...),
				have:   sgPersmissions(port100, cidr, "172.240.2.2/32", "192.168.0.1/32"),
				add:    sgPersmissions(port100, "172.240.1.1/32"),
				remove: sgPersmissions(port100, "172.240.2.2/32"),
			},
		*/
		{
			name:   "Merge want",
			want:   append(sgPermissions(port100, "192.168.0.1/32"), sgPermissions(port100, "172.240.1.1/32")...),
			have:   nil,
			add:    sgPermissions(port100, "192.168.0.1/32", "172.240.1.1/32"),
			remove: nil,
		},
		{
			name:   "Ignore order",
			want:   sgPermissions(port100, "172.240.1.1/32", "192.168.0.1/32", cidr),
			have:   sgPermissions(port100, "192.168.0.1/32", cidr, "172.240.1.1/32"),
			add:    nil,
			remove: nil,
		},
		{
			name: "Ignore protocol case",
			want: []awsec2.IpPermission{
				{
					IpProtocol: aws.String("TCP"),
					FromPort:   &port100,
					ToPort:     &port100,
					IpRanges:   []awsec2.IpRange{{CidrIp: aws.String(cidr)}},
				},
			},
			have: []awsec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   &port100,
					ToPort:     &port100,
					IpRanges:   []awsec2.IpRange{{CidrIp: aws.String(cidr)}},
				},
			},
			add:    nil,
			remove: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			add, remove := DiffPermissions(tc.want, tc.have)

			if diff := cmp.Diff(tc.add, add); diff != "" {
				t.Errorf("r add: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.remove, remove); diff != "" {
				t.Errorf("r remove: -want, +got:\n%s", diff)
			}
		})
	}
}

func BenchmarkDiffPermissions(b *testing.B) {
	var ranges, ranges2, ranges3 []awsec2.IpRange
	for i := 1; i < 255; i++ {
		for j := 0; j < 10; j++ {
			ranges = append(ranges, awsec2.IpRange{
				CidrIp: aws.String(fmt.Sprintf("%d.%d.0.0/24", i, j)),
			})
		}
		ranges2 = append(ranges, awsec2.IpRange{
			CidrIp: aws.String(fmt.Sprintf("%d.1.1.0/24", i)),
		})
		ranges3 = append(ranges, awsec2.IpRange{
			CidrIp: aws.String(fmt.Sprintf("%d.2.2.0/24", i)),
		})
	}

	want := []awsec2.IpPermission{
		{
			IpProtocol: aws.String("TCP"),
			FromPort:   &port100,
			ToPort:     &port100,
			IpRanges:   ranges,
		},
		{
			IpProtocol: aws.String("TCP"),
			FromPort:   &port100,
			ToPort:     &port100,
			IpRanges:   ranges,
		},
		{
			IpProtocol: aws.String("TCP"),
			FromPort:   &port100,
			ToPort:     &port100,
			IpRanges:   ranges2,
		},
	}

	have := []awsec2.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   &port100,
			ToPort:     &port100,
			IpRanges:   ranges,
		},
		{
			IpProtocol: aws.String("TCP"),
			FromPort:   &port100,
			ToPort:     &port100,
			IpRanges:   ranges,
		},
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   &port100,
			ToPort:     &port100,
			IpRanges:   ranges3,
		},
	}

	for i := 0; i < b.N; i++ {
		DiffPermissions(want, have)
	}
}
