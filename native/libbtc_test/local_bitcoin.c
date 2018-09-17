#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#define inline
#endif


#include <btc/utils.h>
#include <btc/ecc_key.h>
#include <btc/tx.h>
#include <btc/chainparams.h>
#include <btc/base58.h>
#include <btc/vector.h>
#include <btc/hash.h>
#include <btc/protocol.h>
#include <btc/tool.h>
#include <btc/bip32.h>
//#include <btc/script.h>

//Crear direccion de testnet
//Mandar bitcoin a direccion de testnet desde un faucet

void get_pubkey_hex_from_wif_priv(const char* priv_key, char* out);

extern void btc_ecc_start();
extern void btc_ecc_stop();

void local_btc(){
    const char* tnet_address = "mi3yrottWLptXAsDQZ3UhyViUkvfMBQWHk";
    const char* privkey_wif = "cMcKgtNcbLWmr6z12HrFaTjq2iKySecy1m74nCYh8R1TNL46gfqS";
    
    const btc_chainparams* chain = &btc_chainparams_test;
    uint8_t* privkey_data = malloc(strlen(privkey_wif));
    size_t outlen = 0;
    outlen = btc_base58_decode_check(privkey_wif, privkey_data, sizeof(privkey_data));
    if (privkey_data[0] != chain->b58prefix_secret_address){
        return;
    }
    
    btc_key key;
    btc_privkey_init(&key);
    memcpy(key.privkey, privkey_data + 1, 32);
    assert(btc_privkey_is_valid(&key) == 1);
    
    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    assert(btc_pubkey_is_valid(&pubkey) == 0);
    btc_pubkey_from_key(&key, &pubkey);
    assert(btc_pubkey_is_valid(&pubkey) == 1);
    
    assert(btc_privkey_verify_pubkey(&key, &pubkey) == 1);
    
    btc_tx* tx = btc_tx_new();
    btc_tx_in *tx_in = btc_tx_in_new();
    
    uint256 prev_tx_id;
    utils_uint256_sethex("2927b98a36169f98f1dae1e2e03856faa4edd080900b604798745cecf7c40fa0", prev_tx_id);
    memcpy(tx_in->prevout.hash, prev_tx_id, sizeof(prev_tx_id));
    tx_in->prevout.n = 0;
    
    tx_in->script_sig = cstr_new_sz(1024);
    vector_add(tx->vin, tx_in);
    
    btc_tx_add_address_out(tx,chain,100000000,tnet_address);
    
    uint160 hash160;
    btc_pubkey_get_hash160(&pubkey, hash160);
    cstring* p2pkh = cstr_new_sz(1024);
    btc_script_build_p2pkh(p2pkh, hash160);
    
    uint256 txhash;
    memset(txhash, 0, sizeof(txhash));
    btc_tx_sighash(tx, p2pkh, 0, SIGHASH_ALL, txhash);
    //btc_tx_hash(tx, txhash); TX ID
    
    unsigned char sig[74];
    size_t sig_outlen = 0;
    btc_key_sign_hash(&key, txhash, sig, &sig_outlen);
	assert(sig_outlen <= 74);
    btc_key_sign_hash(&key, txhash, sig, &sig_outlen);
    
    btc_pubkey_verify_sig(&pubkey, txhash, sig, sig_outlen);
    
    char* script = malloc(1+sig_outlen+2+33);
    script[0] = sig_outlen + 1;
    memcpy(&script[1], sig, sig_outlen);
    script[sig_outlen+1] = 0x01;
    script[sig_outlen+2] = 33;
    memcpy(&script[sig_outlen+3], pubkey.pubkey, 33);
    
    ((btc_tx_in*)tx->vin->data[vector_find(tx->vin, tx_in)])->script_sig = cstr_new_buf(script, sizeof(script));
    
    cstring* tx_ser = cstr_new_sz(1024);
    btc_tx_serialize(tx_ser, tx);
    
    char* raw_tx = malloc(tx_ser->len);
    utils_bin_to_hex((unsigned char*)tx_ser->str, tx_ser->len, raw_tx);
    
    fflush(stdout);
    printf("final tx %s \n",raw_tx);

	free(privkey_data);
	free(script);
	free(raw_tx);
	
}

void create_multisig_script() {
	const char* priv_key_1 = "L3ghwj2zgQnHkfkb5A5m6JTRni3hSZqACjqbuatE2YX99RCwFoky";
	const char* priv_key_2 = "L1cm7DGCsU4XjtQ75oQVTQxk9S274ff6ADnrky7TK9cDTgFFgEd4";
	const char* priv_key_3 = "KwnMaB7b8NMYbBDpoz4B5S3kis2FN5z8pWBHKqTf5vXFrX3wSRaB";

	const char* pkey1 = "03577f6a95a6bfcf4bfa5900be2bce714421a3d025ca47c68e188e5b1e6951eca2";
	const char* pkey2 = "0292e5b1d8471993ceb355a58162d8104312f66d18f236d8ec5bc2bcd1b4b3ad45";
	const char* pkey3 = "0206ad27254ca2858cc53b9de0ab320f4bedfcfb3f08ecf34d16cbf2fb0185d6b5";

	int outlen = 0;
	char pkey1_bin[strlen(pkey1) / 2];
	utils_hex_to_bin(pkey1, pkey1_bin, strlen(pkey1), &outlen);

	outlen = 0;
	char pkey2_bin[strlen(pkey2) / 2];
	utils_hex_to_bin(pkey2, pkey2_bin, strlen(pkey2), &outlen);

	outlen = 0;
	char pkey3_bin[strlen(pkey3) / 2];
	utils_hex_to_bin(pkey3, pkey3_bin, strlen(pkey3), &outlen);

	size_t len = sizeof(pkey3_bin);
	char* redeemScript = malloc(len * 3 + 6);
	redeemScript[0] = OP_2;
	redeemScript[1] = 0x21;
	memcpy(&redeemScript[2], pkey1_bin, len);
	redeemScript[len + 2] = 0x21;
	memcpy(&redeemScript[len + 3], pkey2_bin, len);
	redeemScript[len * 2 + 3] = 0x21;
	memcpy(&redeemScript[len * 2 + 4], pkey3_bin, len);
	redeemScript[len * 3 + 4] = OP_3;
	redeemScript[len * 3 + 5] = OP_CHECKMULTISIG;

	char* raw_script = malloc(len * 3 + 6);
	utils_bin_to_hex(redeemScript, len * 3 + 6, raw_script);
	
	uint160 hash160;
	uint256 hashout;
	btc_hash_sngl_sha256(raw_script, strlen(raw_script), hashout);
	ripemd160(hashout, sizeof(hashout), hash160);

	char b58[sizeof(hash160)];
	btc_base58_encode_check(hash160, sizeof(hash160), b58, sizeof(b58));

	printf("Base 58 encode : %s\n", b58);

	free(redeemScript);
	free(raw_script);
	fflush(stdout);
}

void get_pubkey_hex_from_wif_priv(const char* priv_key, char* out) {
	const btc_chainparams* chain = &btc_chainparams_test;
	uint8_t* privkey_data = malloc(strlen(priv_key));

	size_t outlen = 0;
	outlen = btc_base58_decode_check(priv_key, privkey_data, sizeof(privkey_data));

	btc_key key;
	btc_privkey_init(&key);
	memcpy(key.privkey, privkey_data + 1, 32);

	btc_pubkey pubkey;
	btc_pubkey_init(&pubkey);
	btc_pubkey_from_key(&key, &pubkey);

	utils_bin_to_hex(pubkey.pubkey, BTC_ECKEY_COMPRESSED_LENGTH, out);

	free(privkey_data);
	fflush(stdout);
}

void hd_wallet(){
    btc_hdnode node;
    char master_public[112], master_private[112], address[112];

	// test in https://coinomi.com/recovery-phrase-tool.html
	// can symbol orchard announce gesture horn fashion volume absurd income census stumble across label source
	char xpriv[] = "xprv9s21ZrQH143K2fdZRnZG85AgJLsPZQjZhogase51uSBSGpu76N6fUZ5ZyzZMrCyVyrBgCEQmLfsnRaHbcSGEds4mt3qWyojmP9qqvXqW9QM";
    
    //btc_hdnode_from_seed(utils_hex_to_uint8("6994AFD1725452C936806732537F6C54"), 16, &node);
    
    btc_hdnode_deserialize(xpriv, &btc_chainparams_main, &node);
    
	char path[] = "m/44'/0'/0'/0/5";
    btc_hd_generate_key(&node, path, node.private_key, node.chain_code, false);
    
    btc_hdnode_serialize_private(&node, &btc_chainparams_main, master_private, sizeof(master_private));
    btc_hdnode_serialize_public(&node, &btc_chainparams_main, master_public, sizeof(master_public));
    btc_hdnode_get_p2pkh_address(&node, &btc_chainparams_main, address, sizeof(address));
    
    printf("master private key: %s \n master public key: %s \n",master_private,master_public);
	printf("path %s address: %s \n", path, address);
}


int main(int argc, char** argv) {

	printf("local bitcoin main %s\n", argv[0]);

	btc_ecc_start();

	hd_wallet();
	create_multisig_script();

	btc_ecc_stop();
};
