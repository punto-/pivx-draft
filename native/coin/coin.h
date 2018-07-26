
class Address {

public:
	enum PairStatus {
		
		PAIR_VALID,			// pair is valid, public and private keys check out
		PAIR_INVALID,		// pair is invalid
		PAIR_INCOMPLETE,	// pair is incomplete, only public key is available
	};
	
public:
	
	// a bunch of these for all the formats we need them in
	virtual std::string get_public()=0;
	virtual std::string get_private()=0;

	virtual PairStatus get_status()=0;
	
	virtual ~Address();
};

class Tx {
	
public:
	
	// a bunch of these for all the formats we need them in
	virtual std::string get_serialized()=0;
	
	virtual ~Tx();
};


class Coin {
	
public:
	
	// address
	virtual Address *address_create(void* seed = NULL)=0;

	// transaction
	virtual Tx* tx_begin()=0;
	
	// amount is for reference, so that "get_balance" works correctly
	virtual int tx_add_input(Tx* transaction, std::string src_tx_id, int vout, std::string public_key, std::string private_key, double amount)=0;

	virtual int tx_add_output(Tx* transaction, Address* address, double amount)=0;
	virtual int tx_add_fee(Tx* transaction, double amount)=0;

	virtual double tx_get_balance(Tx* transaction)=0; // should return 0 if fee is accounted for?
	
	virtual int tx_end(Tx* transaction)=0;

	virtual ~Coin();	
};
