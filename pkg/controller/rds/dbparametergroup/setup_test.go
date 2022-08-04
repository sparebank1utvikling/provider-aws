package dbparametergroup

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/rds"
	svcsdk "github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/rds/v1alpha1"
	awsclients "github.com/crossplane-contrib/provider-aws/pkg/clients"
)

type mockRDSClient struct {
	rdsiface.RDSAPI
}

func (m *mockRDSClient) DescribeDBParametersPagesWithContext(ctx context.Context, input *rds.DescribeDBParametersInput, cb func(page *rds.DescribeDBParametersOutput, lastPage bool) bool, _ ...request.Option) error {
	cb(&rds.DescribeDBParametersOutput{
		Parameters: []*svcsdk.Parameter{
			{
				//				ApplyMethod:          new(string),
				DataType:       awsclients.String("list"),
				ParameterName:  awsclients.String("foo"),
				ParameterValue: awsclients.String("a,b, c,  d"),
			},
		},
	}, true)
	return nil
}

func TestIsUpToDate(t *testing.T) {

	c := &custom{
		kube:   nil,
		client: &mockRDSClient{},
	}
	cr := &svcapitypes.DBParameterGroup{
		Spec: svcapitypes.DBParameterGroupSpec{
			ForProvider: svcapitypes.DBParameterGroupParameters{
				CustomDBParameterGroupParameters: svcapitypes.CustomDBParameterGroupParameters{
					Parameters: []svcapitypes.Parameter{
						{
							ParameterName:  awsclients.String("foo"),
							ParameterValue: awsclients.String("a,  b, c,d"),
						},
					},
				},
			},
		},
	}
	obj := &svcsdk.DescribeDBParameterGroupsOutput{}
	got, _ := c.isUpToDate(cr, obj)
	if !got {
		t.Error("should not be up to date")
	}

}
