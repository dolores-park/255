"use strict";

var expect = require('expect.js');
const { Keychain } = require('../password-manager');

describe('Password manager', async function() {
    this.timeout(5000);
    var password = "password123!";

    var kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', async function() {


        it('can dump and restore the database', async function() {
            let keychain = await Keychain.init(password);
            for (var k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            var data = await keychain.dump();
            var contents = data[0];
            var checksum = data[1];
            var newKeychain = await Keychain.load(password, contents, checksum);

            // Make sure it's valid JSON
            expect(async function() {
                JSON.parse(contents)
            }).not.to.throwException();
            for (var k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

    });

});