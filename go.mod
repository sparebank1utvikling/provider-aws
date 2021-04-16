module github.com/crossplane/provider-aws

go 1.16

require (
	github.com/aws/aws-sdk-go v1.37.4
	github.com/aws/aws-sdk-go-v2 v1.9.1
	github.com/aws/aws-sdk-go-v2/config v1.8.2
	github.com/aws/aws-sdk-go-v2/credentials v1.4.2
	github.com/aws/aws-sdk-go-v2/service/acm v1.6.1
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.8.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.18.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.7.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.10.1
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.11.1
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.6.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.10.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.9.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.11.1
	github.com/aws/aws-sdk-go-v2/service/route53 v1.11.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.16.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.8.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.9.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.7.1
	github.com/aws/smithy-go v1.8.0
	github.com/crossplane/crossplane-runtime v0.15.1-0.20210930095326-d5661210733b
	github.com/crossplane/crossplane-tools v0.0.0-20210916125540-071de511ae8e
	github.com/evanphx/json-patch v4.11.0+incompatible
	github.com/go-ini/ini v1.46.0
	github.com/golang/mock v1.5.0
	github.com/google/go-cmp v0.5.6
	github.com/mitchellh/copystructure v1.0.0
	github.com/onsi/gomega v1.14.0
	github.com/pkg/errors v0.9.1
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	sigs.k8s.io/controller-runtime v0.9.6
	sigs.k8s.io/controller-tools v0.6.2
)

replace github.com/crossplane/crossplane-runtime => github.com/larhauga/crossplane-runtime v0.13.1-0.20210415115823-09fdf469261b
