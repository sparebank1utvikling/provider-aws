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
	"bytes"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/kafka"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"

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
			e.delete = e.customDelete
		},
	}

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&svcapitypes.ScramSecretAssociation{}).
		Complete(managed.NewReconciler(mgr,
			cpresource.ManagedKind(svcapitypes.ScramSecretAssociationGroupVersionKind),
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

	add, remove, _, err := e.diff(ctx, cr)
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
		ret, err := e.client.BatchAssociateScramSecret(&svcsdk.BatchAssociateScramSecretInput{
			ClusterArn:    cr.Spec.ForProvider.ClusterARN,
			SecretArnList: add,
		})
		if err != nil {
			return managed.ExternalUpdate{}, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errUpdate)
		}

		if len(ret.UnprocessedScramSecrets) > 0 {
			unprocessedMessage := &bytes.Buffer{}
			for _, unprocessed := range ret.UnprocessedScramSecrets {
				fmt.Fprintf(unprocessedMessage, "%s ", unprocessed.GoString())
			}

			return managed.ExternalUpdate{}, fmt.Errorf("cannot update ScramSecretAssociation has unprocessed secrets: %v", unprocessedMessage.String())
		}

	}
	return managed.ExternalUpdate{}, nil
}

func (e *external) diff(ctx context.Context, cr *svcapitypes.ScramSecretAssociation) (add []*string, remove []*string, count int, err error) {
	input := GenerateListScramSecretsInput(cr)
	resp, err := e.client.ListScramSecretsWithContext(ctx, input)
	if err != nil {
		return nil, nil, 0, err
	}

	add, remove = diff(cr.Spec.ForProvider.SecretARNList, resp.SecretArnList)
	return add, remove, len(resp.SecretArnList), nil
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

	add, remove, count, err := e.diff(ctx, cr)
	if err != nil {
		return managed.ExternalObservation{ResourceExists: false}, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errDescribe)
	}

	resourceExists := true
	if meta.WasDeleted(cr) {
		resourceExists = count > 0
	}

	diff := &bytes.Buffer{}
	for _, v := range add {
		fmt.Fprintf(diff, "+%v ", awsclient.StringValue(v))
	}

	for _, v := range remove {
		fmt.Fprintf(diff, "-%v ", awsclient.StringValue(v))
	}

	upToDate := len(add) == 0 && len(remove) == 0

	cr.SetConditions(xpv1.Available())
	return managed.ExternalObservation{
		ResourceExists:   resourceExists,
		ResourceUpToDate: upToDate,
		Diff:             diff.String(),
		//ResourceLateInitialized: !cmp.Equal(&cr.Spec.ForProvider, currentSpec),
	}, nil
}

func GenerateListScramSecretsInput(cr *svcapitypes.ScramSecretAssociation) *svcsdk.ListScramSecretsInput {
	return &svcsdk.ListScramSecretsInput{
		ClusterArn: cr.Spec.ForProvider.ClusterARN,
	}
}

// GenerateBatchDisassociateScramSecretInput returns a deletion input.
func GenerateBatchDisassociateScramSecretInput(cr *svcapitypes.ScramSecretAssociation) *svcsdk.BatchDisassociateScramSecretInput {
	res := &svcsdk.BatchDisassociateScramSecretInput{}

	if cr.Spec.ForProvider.ClusterARN != nil {
		res.SetClusterArn(*cr.Spec.ForProvider.ClusterARN)
	}

	res.SetSecretArnList(cr.Spec.ForProvider.SecretARNList)

	return res
}

func (e *external) customDelete(ctx context.Context, mg cpresource.Managed) error {
	cr, ok := mg.(*svcapitypes.ScramSecretAssociation)
	if !ok {
		return errors.New(errUnexpectedObject)
	}

	cr.Status.SetConditions(xpv1.Deleting())

	// consider doing a Get first? If we're not up to date
	input := GenerateBatchDisassociateScramSecretInput(cr)
	if len(input.SecretArnList) == 0 {
		return nil
	}
	_, err := e.client.BatchDisassociateScramSecretWithContext(ctx, input)
	// TODO: Check resp, unprocessed secrets are returned
	return awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errDelete)
}
