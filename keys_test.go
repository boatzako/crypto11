package crypto11

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withContext executes a test function with a context.
func withContext(t *testing.T, f func(ctx *Context)) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	f(ctx)
}

func TestFindKeysRequiresIdOrLabel(t *testing.T) {
	withContext(t, func(ctx *Context) {
		_, err := ctx.FindKey(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeys(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeyPair(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeyPairs(nil, nil)
		assert.Error(t, err)
	})
}

func TestFindingKeysWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		label := randomBytes()
		label2 := randomBytes()

		key, err := ctx.GenerateSecretKeyWithLabel(randomBytes(), label, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label2, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label2, 256, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 16)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 32)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})
}

func TestFindingKeyPairsWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {

		// Note: we use common labels, not IDs in this test code. AWS CloudHSM
		// does not accept two keys with the same ID.

		label := randomBytes()
		label2 := randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		_ = attrs.Set(CkaKeyType, pkcs11.CKK_RSA)
		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 3)
	})
}

func TestFindDifferentLabelKeyPair(t *testing.T) {
	withContext(t, func(ctx *Context) {
		prvLabel := randomBytes()
		pubLabel := randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), prvLabel, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), pubLabel, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		_, err = ctx.FindDifferentLabelKeyPair(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindDifferentLabelKeyPair(nil, pubLabel)
		assert.Error(t, err)

		_, err = ctx.FindDifferentLabelKeyPair(prvLabel, nil)
		assert.Error(t, err)

		_, err = ctx.FindDifferentLabelKeyPair(prvLabel, pubLabel)
		require.NoError(t, err)
	})
}

func TestFindDifferentLabelKeyPairs(t *testing.T) {
	withContext(t, func(ctx *Context) {
		prvLabel := randomBytes()
		pubLabel := randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), prvLabel, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), pubLabel, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		_, err = ctx.FindDifferentLabelKeyPairs(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindDifferentLabelKeyPairs(nil, pubLabel)
		assert.Error(t, err)

		_, err = ctx.FindDifferentLabelKeyPairs(prvLabel, nil)
		assert.Error(t, err)

		keys, err := ctx.FindDifferentLabelKeyPairs(prvLabel, pubLabel)
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})
}

func TestFindDifferentLabelKeyPairsWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {

		label := randomBytes()
		label1 := randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)
		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label1, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)
		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label1, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		pubAttrs := NewAttributeSet()
		_ = pubAttrs.Set(CkaLabel, label)
		prvAttrs := NewAttributeSet()
		_ = prvAttrs.Set(CkaLabel, label)

		keys, err := ctx.FindDifferentLabelKeyPairsWithAttributes(pubAttrs, prvAttrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = pubAttrs.Set(CkaLabel, label1)
		_ = prvAttrs.Set(CkaLabel, label1)
		keys, err = ctx.FindDifferentLabelKeyPairsWithAttributes(pubAttrs, prvAttrs)
		require.NoError(t, err)
		require.Len(t, keys, 4)

		pubAttrs = NewAttributeSet()
		prvAttrs = NewAttributeSet()
		_ = pubAttrs.Set(CkaKeyType, pkcs11.CKK_RSA)
		_ = prvAttrs.Set(CkaKeyType, pkcs11.CKK_RSA)
		keys, err = ctx.FindDifferentLabelKeyPairsWithAttributes(pubAttrs, prvAttrs)
		require.NoError(t, err)
		require.Len(t, keys, 9)
	})
}

func TestFindingAllKeys(t *testing.T) {
	withContext(t, func(ctx *Context) {
		for i := 0; i < 10; i++ {
			id := randomBytes()
			key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
			require.NoError(t, err)

			defer func(k *SecretKey) { _ = k.Delete() }(key)
		}

		keys, err := ctx.FindAllKeys()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 10)
	})
}

func TestFindingAllKeyPairs(t *testing.T) {
	withContext(t, func(ctx *Context) {
		for i := 1; i <= 5; i++ {
			id := randomBytes()
			key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
			require.NoError(t, err)

			defer func(k Signer) { _ = k.Delete() }(key)
		}

		keys, err := ctx.FindAllKeyPairs()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 5)
	})
}

func TestGettingPrivateKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaModulus})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Len(t, attrs[CkaModulus].Value, 256)
	})
}

func TestGettingPublicKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs, err := ctx.GetPubAttributes(key, []AttributeType{CkaModulusBits})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(rsaSize), bytesToUlong(attrs[CkaModulusBits].Value))
	})
}

func TestGettingSecretKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaValueLen})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(16), bytesToUlong(attrs[CkaValueLen].Value))
	})
}

func TestGettingUnsupportedKeyTypeAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		key, err := rsa.GenerateKey(rand.Reader, rsaSize)
		require.NoError(t, err)

		_, err = ctx.GetAttributes(key, []AttributeType{CkaModulusBits})
		require.Error(t, err)
	})
}
