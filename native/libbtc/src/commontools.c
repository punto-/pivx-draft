/**********************************************************************
 * Copyright (c) 2016 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <btc/base58.h>
#include <btc/bip32.h>
#include <btc/ecc.h>
#include <btc/ecc_key.h>
#include <btc/net.h>
#include <btc/random.h>
#include <btc/serialize.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _MSC_VER
#include <unistd.h>
//#include <getopt.h>
#endif

btc_bool address_from_pubkey(const btc_chainparams* chain, const char* pubkey_hex, char* address)
{
    if (!pubkey_hex || strlen(pubkey_hex) != 66)
        return false;

    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    pubkey.compressed = 1;

    size_t outlen = 0;
    utils_hex_to_bin(pubkey_hex, pubkey.pubkey, strlen(pubkey_hex), (int*)&outlen);
    assert(btc_pubkey_is_valid(&pubkey) == 1);

    uint8_t hash160[sizeof(uint160)+1];
    hash160[0] = chain->b58prefix_pubkey_address;
    btc_pubkey_get_hash160(&pubkey, hash160 + 1);

    btc_base58_encode_check(hash160, sizeof(hash160), address, 98);

    return true;
}

btc_bool pubkey_from_privatekey(const btc_chainparams* chain, const char* privkey_wif, char* pubkey_hex, size_t* sizeout)
{
    uint8_t* privkey_data = (uint8_t*)alloca(strlen(privkey_wif));
    size_t outlen = 0;
    outlen = btc_base58_decode_check(privkey_wif, privkey_data, sizeof(privkey_data));
    if (privkey_data[0] != chain->b58prefix_secret_address)
        return false;

    btc_key key;
    btc_privkey_init(&key);
    memcpy(key.privkey, privkey_data + 1, 32);

    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    assert(btc_pubkey_is_valid(&pubkey) == 0);
    btc_pubkey_from_key(&key, &pubkey);
    btc_privkey_cleanse(&key);

    btc_pubkey_get_hex(&pubkey, pubkey_hex, sizeout);
    btc_pubkey_cleanse(&pubkey);

    return true;
}

btc_bool gen_privatekey(const btc_chainparams* chain, char* privkey_wif, size_t strsize_wif, char* privkey_hex_or_null)
{
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */

    btc_key key;
    btc_privkey_init(&key);
    btc_privkey_gen(&key);
    memcpy(&pkeybase58c[1], key.privkey, BTC_ECKEY_PKEY_LENGTH);
    assert(btc_base58_encode_check(pkeybase58c, 34, privkey_wif, strsize_wif) != 0);

    // also export the hex privkey if use had passed in a valid pointer
    // will always export 32 bytes
    if (privkey_hex_or_null != NULL)
        utils_bin_to_hex(key.privkey, BTC_ECKEY_PKEY_LENGTH, privkey_hex_or_null);
    btc_privkey_cleanse(&key);
    return true;
}

btc_bool hd_gen_master(const btc_chainparams* chain, char* masterkeyhex, size_t strsize)
{
    btc_hdnode node;
    uint8_t seed[32];
    assert(btc_random_bytes(seed, 32, true));
    btc_hdnode_from_seed(seed, 32, &node);
    memset(seed, 0, 32);
    btc_hdnode_serialize_private(&node, chain, masterkeyhex, strsize);
    memset(&node, 0, sizeof(node));
    return true;
}

btc_bool hd_print_node(const btc_chainparams* chain, const char* nodeser)
{
    btc_hdnode node;
    if (!btc_hdnode_deserialize(nodeser, chain, &node))
        return false;

    size_t strsize = 128;
    char *str = (char*)alloca(strsize);
    btc_hdnode_get_p2pkh_address(&node, chain, str, strsize);

    printf("ext key: %s\n", nodeser);

    size_t privkey_wif_size_bin = 34;
    uint8_t *pkeybase58c = (uint8_t*)alloca(privkey_wif_size_bin);
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */
    size_t privkey_wif_size = 128;
    char *privkey_wif = (char*)alloca(privkey_wif_size);
    memcpy(&pkeybase58c[1], node.private_key, BTC_ECKEY_PKEY_LENGTH);
    assert(btc_base58_encode_check(pkeybase58c, privkey_wif_size_bin, privkey_wif, privkey_wif_size) != 0);
    printf("privatekey WIF: %s\n", privkey_wif);

    printf("depth: %d\n", node.depth);
    printf("p2pkh address: %s\n", str);

    if (!btc_hdnode_get_pub_hex(&node, str, &strsize))
        return false;
    printf("pubkey hex: %s\n", str);

    strsize = 128;
    btc_hdnode_serialize_public(&node, chain, str, strsize);
    printf("extended pubkey: %s\n", str);
    return true;
}

btc_bool hd_derive(const btc_chainparams* chain, const char* masterkey, const char* keypath, char* extkeyout, size_t extkeyout_size)
{
    btc_hdnode node, nodenew;
    if (!btc_hdnode_deserialize(masterkey, chain, &node))
        return false;

    //check if we only have the publickey
    bool pubckd = !btc_hdnode_has_privkey(&node);

    //derive child key, use pubckd or privckd
    if (!btc_hd_generate_key(&nodenew, keypath, pubckd ? node.public_key : node.private_key, node.chain_code, pubckd))
        return false;

    if (pubckd)
        btc_hdnode_serialize_public(&nodenew, chain, extkeyout, extkeyout_size);
    else
        btc_hdnode_serialize_private(&nodenew, chain, extkeyout, extkeyout_size);
    return true;
}
