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

// Code generated by ack-generate. DO NOT EDIT.

package scramsecretassociation

import (
	"context"

	svcapi "github.com/aws/aws-sdk-go/service/kafka"
	svcsdk "github.com/aws/aws-sdk-go/service/kafka"
	svcsdkapi "github.com/aws/aws-sdk-go/service/kafka/kafkaiface"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	cpresource "github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane-contrib/provider-aws/apis/kafka/v1alpha1"
	awsclient "github.com/crossplane-contrib/provider-aws/pkg/clients"
)

const (
	errUnexpectedObject = "managed resource is not an ScramSecretAssociation resource"

	errCreateSession = "cannot create a new session"
	errCreate        = "cannot create ScramSecretAssociation in AWS"
	errUpdate        = "cannot update ScramSecretAssociation in AWS"
	errDescribe      = "failed to describe ScramSecretAssociation"
	errDelete        = "failed to delete ScramSecretAssociation"
)

type connector struct {
	kube client.Client
	opts []option
}

func (c *connector) Connect(ctx context.Context, mg cpresource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*svcapitypes.ScramSecretAssociation)
	if !ok {
		return nil, errors.New(errUnexpectedObject)
	}
	sess, err := awsclient.GetConfigV1(ctx, c.kube, mg, cr.Spec.ForProvider.Region)
	if err != nil {
		return nil, errors.Wrap(err, errCreateSession)
	}
	return newExternal(c.kube, svcapi.New(sess), c.opts), nil
}

func (e *external) Observe(ctx context.Context, mg cpresource.Managed) (managed.ExternalObservation, error) {
	return e.observe(ctx, mg)
}

func (e *external) Create(ctx context.Context, mg cpresource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*svcapitypes.ScramSecretAssociation)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Creating())
	input := GenerateBatchAssociateScramSecretInput(cr)
	if err := e.preCreate(ctx, cr, input); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "pre-create failed")
	}
	resp, err := e.client.BatchAssociateScramSecretWithContext(ctx, input)
	if err != nil {
		return managed.ExternalCreation{}, awsclient.Wrap(err, errCreate)
	}

	if resp.ClusterArn != nil {
		cr.Status.AtProvider.ClusterARN = resp.ClusterArn
	} else {
		cr.Status.AtProvider.ClusterARN = nil
	}

	return e.postCreate(ctx, cr, resp, managed.ExternalCreation{}, err)
}

func (e *external) Update(ctx context.Context, mg cpresource.Managed) (managed.ExternalUpdate, error) {
	return e.update(ctx, mg)

}

func (e *external) Delete(ctx context.Context, mg cpresource.Managed) error {
	cr, ok := mg.(*svcapitypes.ScramSecretAssociation)
	if !ok {
		return errors.New(errUnexpectedObject)
	}
	cr.Status.SetConditions(xpv1.Deleting())
	input := GenerateBatchDisassociateScramSecretInput(cr)
	ignore, err := e.preDelete(ctx, cr, input)
	if err != nil {
		return errors.Wrap(err, "pre-delete failed")
	}
	if ignore {
		return nil
	}
	resp, err := e.client.BatchDisassociateScramSecretWithContext(ctx, input)
	return e.postDelete(ctx, cr, resp, awsclient.Wrap(cpresource.Ignore(IsNotFound, err), errDelete))
}

type option func(*external)

func newExternal(kube client.Client, client svcsdkapi.KafkaAPI, opts []option) *external {
	e := &external{
		kube:       kube,
		client:     client,
		observe:    nopObserve,
		preCreate:  nopPreCreate,
		postCreate: nopPostCreate,
		preDelete:  nopPreDelete,
		postDelete: nopPostDelete,
		update:     nopUpdate,
	}
	for _, f := range opts {
		f(e)
	}
	return e
}

type external struct {
	kube       client.Client
	client     svcsdkapi.KafkaAPI
	observe    func(context.Context, cpresource.Managed) (managed.ExternalObservation, error)
	preCreate  func(context.Context, *svcapitypes.ScramSecretAssociation, *svcsdk.BatchAssociateScramSecretInput) error
	postCreate func(context.Context, *svcapitypes.ScramSecretAssociation, *svcsdk.BatchAssociateScramSecretOutput, managed.ExternalCreation, error) (managed.ExternalCreation, error)
	preDelete  func(context.Context, *svcapitypes.ScramSecretAssociation, *svcsdk.BatchDisassociateScramSecretInput) (bool, error)
	postDelete func(context.Context, *svcapitypes.ScramSecretAssociation, *svcsdk.BatchDisassociateScramSecretOutput, error) error
	update     func(context.Context, cpresource.Managed) (managed.ExternalUpdate, error)
}

func nopObserve(context.Context, cpresource.Managed) (managed.ExternalObservation, error) {
	return managed.ExternalObservation{}, nil
}

func nopPreCreate(context.Context, *svcapitypes.ScramSecretAssociation, *svcsdk.BatchAssociateScramSecretInput) error {
	return nil
}
func nopPostCreate(_ context.Context, _ *svcapitypes.ScramSecretAssociation, _ *svcsdk.BatchAssociateScramSecretOutput, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}
func nopPreDelete(context.Context, *svcapitypes.ScramSecretAssociation, *svcsdk.BatchDisassociateScramSecretInput) (bool, error) {
	return false, nil
}
func nopPostDelete(_ context.Context, _ *svcapitypes.ScramSecretAssociation, _ *svcsdk.BatchDisassociateScramSecretOutput, err error) error {
	return err
}
func nopUpdate(context.Context, cpresource.Managed) (managed.ExternalUpdate, error) {
	return managed.ExternalUpdate{}, nil
}
