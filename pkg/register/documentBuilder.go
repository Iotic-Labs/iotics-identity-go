// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
)

const defaultVersion = "0.0.1"

var supportedVersions = []string{"0.0.0", "0.0.1"}

// RegisterDocumentBuilder is used to create RegisterDocument
// but uses maps instead of slices so that we can better handle keys by name
// NOTE: is this really necessary? we could let the client to set the RegisterDocument correctly
// with some validation to take care of edge cases if someone would add the same name/ID multiple times?
type RegisterDocumentBuilder struct {
	ID                     string
	Purpose                string
	Proof                  string
	Revoked                bool
	Metadata               Metadata
	Creator                string
	SpecVersion            string
	UpdateTime             int64
	Controller             string
	PublicKeys             map[string]*RegisterPublicKey
	AuthenticationKeys     map[string]*RegisterPublicKey
	DelegateAuthentication map[string]*RegisterDelegationProof
	DelegateControl        map[string]*RegisterDelegationProof
}

func defaultUpdateTimeSeconds() int64 {
	return time.Now().Unix()
}

func specVersionExists(val string) bool {
	for _, v := range supportedVersions {
		if v == val {
			return true
		}
	}
	return false
}

// RegisterDocumentOpts document builder options holder type
type RegisterDocumentOpts func(builder *RegisterDocumentBuilder) error

// NewRegisterDocument Build a valid immutable register document.
func NewRegisterDocument(opts []RegisterDocumentOpts) (*RegisterDocument, []error) {
	builder := &RegisterDocumentBuilder{}

	var errs []error
	for _, o := range opts {
		err := o(builder)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return nil, errs
	}

	doc, err := builder.build()
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, doc.Validate()...)
	if len(errs) != 0 {
		return nil, errs
	}

	return doc, nil
}

func (b RegisterDocumentBuilder) build() (*RegisterDocument, error) {
	specVersion := defaultVersion
	if b.SpecVersion != "" {
		specVersion = b.SpecVersion
	}

	updateTime := defaultUpdateTimeSeconds()
	if b.UpdateTime != 0 {
		updateTime = b.UpdateTime
	}

	doc := &RegisterDocument{
		Context:                DocumentContext,
		ID:                     b.ID,
		IoticsSpecVersion:      specVersion,
		IoticsDIDType:          b.Purpose,
		Controller:             b.Controller,
		Creator:                b.Creator,
		UpdateTime:             updateTime,
		Proof:                  b.Proof,
		Revoked:                b.Revoked,
		AuthenticationKeys:     convertRegisterPublicKeyMapToSlice(b.AuthenticationKeys),
		PublicKeys:             convertRegisterPublicKeyMapToSlice(b.PublicKeys),
		DelegateAuthentication: convertRegisterDelegationProofMapToSlice(b.DelegateAuthentication),
		DelegateControl:        convertRegisterDelegationProofMapToSlice(b.DelegateControl),
		Metadata:               b.Metadata,
	}

	return doc, nil
}

func (b RegisterDocumentBuilder) remove(name string) {
	// NOTE: the original name in Python version was remove_key
	delete(b.PublicKeys, name)
	delete(b.AuthenticationKeys, name)
	delete(b.DelegateControl, name)
	delete(b.DelegateAuthentication, name)
}

// CloneRegisterPublicKey Clone a RegisterPublicKey
func CloneRegisterPublicKey(obj map[string]*RegisterPublicKey) map[string]*RegisterPublicKey {
	publicKeys := map[string]*RegisterPublicKey{}
	for k, v := range obj {
		cloned, _ := v.Clone()
		publicKeys[k] = cloned
	}
	return publicKeys
}

// CloneRegisterDelegationProof Clone a RegisterDelegationProof
func CloneRegisterDelegationProof(obj map[string]*RegisterDelegationProof) map[string]*RegisterDelegationProof {
	newMap := map[string]*RegisterDelegationProof{}
	for k, v := range obj {
		cloned, _ := v.Clone()
		newMap[k] = cloned
	}
	return newMap
}

// Clone a RegisterDocumentBuilder
func (b RegisterDocumentBuilder) Clone() *RegisterDocumentBuilder {
	// NOTE: the original name in Python version was set_keys_from_existing
	clone := &RegisterDocumentBuilder{
		PublicKeys:             CloneRegisterPublicKey(b.PublicKeys),
		AuthenticationKeys:     CloneRegisterPublicKey(b.AuthenticationKeys),
		DelegateAuthentication: CloneRegisterDelegationProof(b.DelegateAuthentication),
		DelegateControl:        CloneRegisterDelegationProof(b.DelegateControl),
		Revoked:                b.Revoked,
	}
	return clone
}

// AddFromExistingDocument Build a new document from an existing one
func AddFromExistingDocument(doc *RegisterDocument) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		builder.ID = doc.ID
		builder.Purpose = doc.IoticsDIDType
		builder.Proof = doc.Proof
		builder.Revoked = doc.Revoked
		builder.Controller = doc.Controller
		builder.Creator = doc.Creator
		builder.SpecVersion = doc.IoticsSpecVersion
		builder.PublicKeys = convertReturnPublicKeySliceToMap(doc.PublicKeys)
		builder.AuthenticationKeys = convertReturnPublicKeySliceToMap(doc.AuthenticationKeys)
		builder.DelegateControl = convertReturnDelegationSliceToMap(doc.DelegateControl)
		builder.DelegateAuthentication = convertReturnDelegationSliceToMap(doc.DelegateAuthentication)
		builder.Metadata = Metadata{
			Label:   doc.Metadata.Label,
			Comment: doc.Metadata.Comment,
			URL:     doc.Metadata.URL,
		}
		return nil
	}
}

// AddRootParams Add root parameters ID, Purpose, Proof, Revoked
func AddRootParams(id string, purpose identity.DidType, proof string, revoked bool) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		builder.ID = id
		builder.Purpose = purpose.String()
		builder.Proof = proof
		builder.Revoked = revoked
		return nil
	}
}

// AddPublicKey returns a function which will add a public key to the RegisterDocument
// this function is idempotent, so if the same key (with the same name/ID) is added, it overwrites the previous one
func AddPublicKey(name string, publicKeyBase58 string, revoked bool) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		obj, err := NewRegisterPublicKey(name, PublicKeyType, publicKeyBase58, revoked)
		if err != nil {
			return err
		}
		if builder.PublicKeys == nil {
			builder.PublicKeys = map[string]*RegisterPublicKey{}
		}
		builder.PublicKeys[name] = obj
		return nil
	}
}

// AddPublicKeyObj add RegisterPublicKey object
func AddPublicKeyObj(obj *RegisterPublicKey) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		if builder.PublicKeys == nil {
			builder.PublicKeys = map[string]*RegisterPublicKey{}
		}
		builder.PublicKeys[obj.ID] = obj
		return nil
	}
}

// AddAuthenticationKey returns a function which will add an authentication key to the RegisterDocument
// this function is idempotent, so if the same key (with the same name/ID) is added, it overwrites the previous one
func AddAuthenticationKey(name string, publicKeyBase58 string, revoked bool) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		obj, err := NewRegisterPublicKey(name, AuthenticationKeyType, publicKeyBase58, revoked)
		if err != nil {
			return err
		}
		if builder.AuthenticationKeys == nil {
			builder.AuthenticationKeys = map[string]*RegisterPublicKey{}
		}
		builder.AuthenticationKeys[name] = obj
		return nil
	}
}

// AddAuthenticationKeyObj add RegisterPublicKey object
func AddAuthenticationKeyObj(obj *RegisterPublicKey) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		if builder.AuthenticationKeys == nil {
			builder.AuthenticationKeys = map[string]*RegisterPublicKey{}
		}
		builder.AuthenticationKeys[obj.ID] = obj
		return nil
	}
}

// AddControlDelegation returns a function which will add control delegation to the RegisterDocument
// this function is idempotent, so if the same key (with the same name/ID) is added, it overwrites the previous one
func AddControlDelegation(name string, controller string, proof string, revoked bool) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		obj, err := NewRegisterDelegationProof(name, controller, proof, revoked)
		if err != nil {
			return err
		}
		if builder.DelegateControl == nil {
			builder.DelegateControl = map[string]*RegisterDelegationProof{}
		}
		builder.DelegateControl[name] = obj
		return nil
	}
}

// AddControlDelegationObj add RegisterDelegationProof object
func AddControlDelegationObj(obj *RegisterDelegationProof) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		if builder.DelegateControl == nil {
			builder.DelegateControl = map[string]*RegisterDelegationProof{}
		}
		builder.DelegateControl[obj.ID] = obj
		return nil
	}
}

// AddAuthenticationDelegation returns a function which will add authentication delegation to the RegisterDocument
// this function is idempotent, so if the same key (with the same name/ID) is added, it overwrites the previous one
func AddAuthenticationDelegation(name string, controller string, proof string, revoked bool) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		obj, err := NewRegisterDelegationProof(name, controller, proof, revoked)
		if err != nil {
			return err
		}
		if builder.DelegateAuthentication == nil {
			builder.DelegateAuthentication = map[string]*RegisterDelegationProof{}
		}
		builder.DelegateAuthentication[name] = obj
		return nil
	}
}

// AddAuthenticationDelegationObj Add RegisterDelegationProof object
func AddAuthenticationDelegationObj(obj *RegisterDelegationProof) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		// NOTE: this is different to the Python version, which is not idempotent but raises an error
		if builder.DelegateAuthentication == nil {
			builder.DelegateAuthentication = map[string]*RegisterDelegationProof{}
		}
		builder.DelegateAuthentication[obj.ID] = obj
		return nil
	}
}

// SetDocumentRevoked Set document revoked
func SetDocumentRevoked(revoked bool) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		builder.Revoked = revoked
		return nil
	}
}

// SetDocumentController Set document controller
func SetDocumentController(controller string) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		builder.Controller = controller
		return nil
	}
}

// SetDocumentCreator Set document creator
func SetDocumentCreator(creator string) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		builder.Creator = creator
		return nil
	}
}

// RemoveKey returns a function which will remove a key or delegation from the RegisterDocument if it exists
func RemoveKey(name string) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		delete(builder.PublicKeys, name)
		delete(builder.AuthenticationKeys, name)
		delete(builder.DelegateControl, name)
		delete(builder.DelegateAuthentication, name)
		return nil
	}
}

// RevokeKey returns a function which will remove a key or delegation from the RegisterDocument if it exists
func RevokeKey(name string) RegisterDocumentOpts {
	return func(builder *RegisterDocumentBuilder) error {
		item, ok := builder.PublicKeys[name]
		if ok {
			item.Revoked = true
		}
		item, ok = builder.AuthenticationKeys[name]
		if ok {
			item.Revoked = true
		}
		ditem, ok := builder.DelegateControl[name]
		if ok {
			ditem.Revoked = true
		}
		ditem, ok = builder.DelegateAuthentication[name]
		if ok {
			ditem.Revoked = true
		}
		return nil
	}
}
