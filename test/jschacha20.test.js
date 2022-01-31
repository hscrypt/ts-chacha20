/**
 * Created by Mykola Bubelich
 * 2017-01-25
 */

import { Chacha20 } from '../src/chacha20'
import 'jest-expect-message'

/**
 * General Test
 */
test("Class 'Chacha20' should exist", () => {
  const salsa = new Chacha20(new Uint8Array(32), new Uint8Array(12))
  expect(salsa instanceof Chacha20).toBe(true)
})

test("Function 'encrypt' should exist", () => {
  const salsa = new Chacha20(new Uint8Array(32), new Uint8Array(12))
  expect(typeof salsa.encrypt).toBe('function')
})

test("Function 'decrypt' should exist", () => {
  const salsa = new Chacha20(new Uint8Array(32), new Uint8Array(12))
  expect(typeof salsa.decrypt).toBe('function')
})

/**
 * Errors handlers
 */
test('When set key with length not 32 byte, error should be thrown', () => {
  expect(() => {
    new Chacha20(null, null)
  }, "Key should be 32 byte array!").toThrow()
})

test('When set nonce with length not 12 byte, error should be thrown', () => {
  expect(() => {
    new Chacha20(new Uint8Array(32), null)
  }, "Nonce should be 12 byte array!").toThrow()
})

test('When not bytes pass to encryt/decrypt method, error should be thrown', () => {
  expect(() => {
    new Chacha20(new Uint8Array(32), new Uint8Array(12)).encrypt(null)
  }, "Data should be type of bytes \(Uint8Array\) and not empty!").toThrow()
})

/**
 * Encrypt / Decrypt
 */
test('Encrypt and decrypt for 256 byte should be same', () => {
  const crypto = require('crypto')

  const key = new Uint8Array(crypto.randomBytes(32))
  const nonce = new Uint8Array(crypto.randomBytes(12))
  const data = new Uint8Array(crypto.randomBytes(4096))

  const encoder = new Chacha20(key, nonce)
  const decoder = new Chacha20(key, nonce)

  const encr = encoder.encrypt(data)
  const decr = decoder.decrypt(encr)

  expect(encoder.param, 'Parameters should be equivalent').toEqual(decoder.param)
  expect(data, 'Decrypted data should be the same as input').toEqual(decr)
  expect([encoder._param[12], decoder._param[12]], 'Counter should be equal 64').toEqual([64, 64])
})

test('First block and param should be equal to reference', () => {
  const key = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f
  ])

  const nonce = new Uint8Array([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
  ])

  const counter = 1

  const text = new Uint8Array([
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e
  ])

  // encrypt
  const encryptor = new Chacha20(key, nonce, counter)
  const ciphertext = encryptor.encrypt(text)

  // decrypt
  const decryptor = new Chacha20(key, nonce, counter)
  const plaintext = decryptor.decrypt(ciphertext)

  expect(plaintext, 'Test text should be the same').toEqual(text)
  expect(encryptor._param, 'Param should be the same for encryptor and decryptor').toEqual(decryptor._param)
  expect(encryptor._keystream, 'Keystream should be the same for encryptor and decryptor').toEqual(decryptor._keystream)
})
