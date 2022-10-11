package filter

import (
	"log"
	"reflect"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func GetResourceStatus(a any) *xpv1.ResourceStatus {
	status := reflect.ValueOf(a).Elem().FieldByName("Status").FieldByName("ResourceStatus").Interface()
	if s, ok := status.(xpv1.ResourceStatus); ok {
		return &s
	}
	log.Printf("Could not get resource status %T %t", status, status)
	return nil
}

var Filter = predicate.Funcs{
	// https://stuartleeks.com/posts/kubebuilder-event-filters-part-2-update/
	UpdateFunc: func(e event.UpdateEvent) bool {
		diff := cmp.Diff(e.ObjectOld, e.ObjectNew)
		log.Println(diff)
		if res := GetResourceStatus(e.ObjectNew); res != nil {
			ready := res.GetCondition(xpv1.TypeReady).Status == v1.ConditionTrue
			synced := res.GetCondition(xpv1.TypeSynced).Status == v1.ConditionTrue
			oldGeneration := e.ObjectOld.GetGeneration()
			newGeneration := e.ObjectNew.GetGeneration()
			// Generation is only updated on spec changes (also on deletion),
			// not metadata or status
			// Filter out events where the generation hasn't changed to
			// avoid being triggered by status updates

			// TODO: This also excludes a change if you add a custom label/annotation manually to trigger reconcile

			log.Println("filter event?", "gen equals", oldGeneration == newGeneration, "ready", ready, "synced", synced)
			if oldGeneration == newGeneration && ready && synced {
				return false
			}
		}

		return true
	},
	DeleteFunc: func(e event.DeleteEvent) bool {
		// The reconciler adds a finalizer so we perform clean-up
		// when the delete timestamp is added
		// Suppress Delete events to avoid filtering them out in the Reconcile function
		return true
	},
}
