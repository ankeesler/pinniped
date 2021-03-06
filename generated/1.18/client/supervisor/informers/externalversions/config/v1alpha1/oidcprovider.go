// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	configv1alpha1 "go.pinniped.dev/generated/1.18/apis/supervisor/config/v1alpha1"
	versioned "go.pinniped.dev/generated/1.18/client/supervisor/clientset/versioned"
	internalinterfaces "go.pinniped.dev/generated/1.18/client/supervisor/informers/externalversions/internalinterfaces"
	v1alpha1 "go.pinniped.dev/generated/1.18/client/supervisor/listers/config/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// OIDCProviderInformer provides access to a shared informer and lister for
// OIDCProviders.
type OIDCProviderInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.OIDCProviderLister
}

type oIDCProviderInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewOIDCProviderInformer constructs a new informer for OIDCProvider type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewOIDCProviderInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredOIDCProviderInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredOIDCProviderInformer constructs a new informer for OIDCProvider type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredOIDCProviderInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ConfigV1alpha1().OIDCProviders(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ConfigV1alpha1().OIDCProviders(namespace).Watch(context.TODO(), options)
			},
		},
		&configv1alpha1.OIDCProvider{},
		resyncPeriod,
		indexers,
	)
}

func (f *oIDCProviderInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredOIDCProviderInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *oIDCProviderInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&configv1alpha1.OIDCProvider{}, f.defaultInformer)
}

func (f *oIDCProviderInformer) Lister() v1alpha1.OIDCProviderLister {
	return v1alpha1.NewOIDCProviderLister(f.Informer().GetIndexer())
}
