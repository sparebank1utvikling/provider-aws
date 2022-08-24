/*
Copyright 2022 The Crossplane Authors.
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

package scramsecretassociation

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/kafka"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/kafka/v1alpha1"
	"github.com/crossplane-contrib/provider-aws/apis/v1alpha1"
	awsclient "github.com/crossplane-contrib/provider-aws/pkg/clients"
	"github.com/crossplane-contrib/provider-aws/pkg/features"
)

// SetupScramSecretAssociation adds a controller that reconciles ScramSecretAssociation.
func SetupScramSecretAssociation(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(svcapitypes.ScramSecretAssociationGroupKind)
	opts := []option{
		func(e *external) {
			e.update = e.customUpdate
			e.observe = e.customObserve
		},
	}

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&svcapitypes.Configuration{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.ConfigurationGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
			managed.WithPollInterval(o.PollInterval),
			managed.WithLogger(o.Logger.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
			managed.WithMetricsReconciler(o.MetricsReconciler),
			managed.WithConnectionPublishers(cps...)))
}

func diff(desired, current []*string) (add, remove []*string) {
	got := make(map[string]bool, len(current))
	for _, arn := range current {
		got[aws.StringValue(arn)] = true
	}

	want := make(map[string]bool, len(desired))
	for _, arn := range desired {
		want[aws.StringValue(arn)] = true
		if !got[aws.StringValue(arn)] {
			add = append(add, arn)
		}
	}

	for _, arn := range current {
		if !want[aws.StringValue(arn)] {
			remove = append(remove, arn)
		}
	}
	return
}

func isUpToDate(cr *svcapitypes.ScramSecretAssociation, resp *svcsdk.ListScramSecretsOutput) (bool, error) {
	add, remove := diff(cr.Spec.ForProvider.SecretARNList, resp.SecretArnList)

	return len(add) == 0 && len(remove) == 0, nil
}

func (e *external) customUpdate(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.ScramSecretAssociation)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}

	add, remove, err := e.diff(ctx, cr)
	if err != nil {
		return managed.ExternalUpdate{}, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}

	if len(remove) != 0 {
		e.client.BatchDisassociateScramSecret(&svcsdk.BatchDisassociateScramSecretInput{
			ClusterArn:    cr.Spec.ForProvider.ClusterARN,
			SecretArnList: remove,
		})
		if err != nil {
			return managed.ExternalUpdate{}, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errUpdate)
		}
	}
	if len(add) != 0 {
		_, err := e.client.BatchAssociateScramSecret(&svcsdk.BatchAssociateScramSecretInput{
			ClusterArn:    cr.Spec.ForProvider.ClusterARN,
			SecretArnList: add,
		})
		if err != nil {
			return managed.ExternalUpdate{}, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errUpdate)
		}

	}
	return managed.ExternalUpdate{}, nil
}

func (e *external) diff(ctx context.Context, cr *svcapitypes.ScramSecretAssociation) (add []*string, remove []*string, err error) {
	input := GenerateListScramSecretsInput(cr)
	resp, err := e.client.ListScramSecretsWithContext(ctx, input)
	if err != nil {
		return nil, nil, err
	}

	add, remove = diff(cr.Spec.ForProvider.SecretARNList, resp.SecretArnList)
	return add, remove, nil
}

func (e *external) customObserve(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*svcapitypes.ScramSecretAssociation)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errUnexpectedObject)
	}
	/*
		if meta.GetExternalName(cr) == "" {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
	*/

	add, remove, err := e.diff(ctx, cr)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}

	upToDate := len(add) == 0 && len(remove) == 0
	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: upToDate,
		//ResourceLateInitialized: !cmp.Equal(&cr.Spec.ForProvider, currentSpec),
	}, nil
}

func GenerateListScramSecretsInput(cr *svcapitypes.ScramSecretAssociation) *svcsdk.ListScramSecretsInput {
	return &svcsdk.ListScramSecretsInput{
		ClusterArn: cr.Spec.ForProvider.ClusterARN,
	}
}

/*
func GenerateScramSecretAssociation(resp *svcsdk.ListScramSecretsOutput) *svcapitypes.ScramSecretAssociation {
	return &svcapitypes.ScramSecretAssociation{
		Spec:       svcapitypes.ScramSecretAssociationSpec{},
		Status:     svcapitypes.ScramSecretAssociationStatus{
			ResourceStatus: v1.ResourceStatus{},
			AtProvider:     svcapitypes.ScramSecretAssociationObservation{
				ClusterARN: resp.,
			},
		},
	}
}
*/

/*
func preCreate(_ context.Context, cr *svcapitypes.Configuration, obj *svcsdk.CreateConfigurationInput) error {
	obj.Name = awsclients.String(meta.GetExternalName(cr))
	serverProperties := strings.Join(cr.Spec.ForProvider.Properties, "\n")
	obj.ServerProperties = []byte(serverProperties)
	return nil
}

func postCreate(_ context.Context, cr *svcapitypes.Configuration, obj *svcsdk.CreateConfigurationOutput, _ managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, awsclients.StringValue(obj.Arn))
	return managed.ExternalCreation{ExternalNameAssigned: true}, nil
}

func preObserve(_ context.Context, cr *svcapitypes.Configuration, obj *svcsdk.DescribeConfigurationInput) error {
	obj.Arn = awsclients.String(meta.GetExternalName(cr))
	return nil
}

func postObserve(_ context.Context, cr *svcapitypes.Configuration, obj *svcsdk.DescribeConfigurationOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	switch awsclients.StringValue(obj.State) {
	case string(svcapitypes.ConfigurationState_ACTIVE):
		cr.SetConditions(xpv1.Available())
	case string(svcapitypes.ConfigurationState_DELETING):
		cr.SetConditions(xpv1.Deleting())
	}

	return obs, nil
}

func preDelete(_ context.Context, cr *svcapitypes.Configuration, obj *svcsdk.DeleteConfigurationInput) (bool, error) {
	obj.Arn = awsclients.String(meta.GetExternalName(cr))
	return false, nil
}

func postDelete(_ context.Context, cr *svcapitypes.Configuration, obj *svcsdk.DeleteConfigurationOutput, err error) error {
	if err != nil {
		if strings.Contains(err.Error(), svcsdk.ErrCodeBadRequestException) {
			// skip: failed to delete Configuration: BadRequestException:
			// This operation is only valid for resources that are in one of
			// the following states :[ACTIVE, DELETE_FAILED]
			return nil
		}
		return err
	}
	return err
}
*/
