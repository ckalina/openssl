#!/usr/bin/bash
hash_ref() {
	echo -n $1 \
	| ./argon2-ref "$2" -$4 -t 3 -m 3 -p 1 -l $3 \
	| grep '^Hash:' | awk '{print $2;}'
}

hash_openssl() {
	./main "$1" "$2" $3 | tail -n 1
}

[[ -z $1 ]] && cnt=1000 || cnt=$1

export LD_LIBRARY_PATH=../openssl-argon2/
for type in d i id; do
make CFLAGS=-DARGON2$(echo $type | tr '[:lower:]' '[:upper:]') OPENSSL_LIB="../openssl-argon2/" || exit

for mem in 32 64 124 128; do
for i in `seq 1 $cnt`; do
for input in `head -n 10 /dev/urandom | base64 | tr -d '\n'`; do # 77 chars input
	salt=${input:51:61}
	input=${input:0:50}
	ref=`hash_ref $input $salt $mem $type`
	ossl=`hash_openssl $input $salt $mem $type`
	ossl_ret=$?
	stat=`bash -c "diff <(echo $ref) <(echo $ossl) &> /dev/null && echo -e \"\e[32mMATCH\e[39m\" || echo -e \"\e[31mFAIL\e[39m\""`
	stat_raw=`bash -c "diff <(echo $ref) <(echo $ossl) &> /dev/null && echo -e \"MATCH\" || echo -e \"FAIL\""`
	printf "[%4s Argon2$type\t%s $ossl_ret]\tMem: %5s Input: %50s Salt: %11s RefMD: %64s OpenSSLMD: %64s\n" "#$i" "$stat" $mem "$input" "$salt" $ref $ossl
	printf "[%4s Argon2$type\t%s $ossl_ret]\tMem: %5s Input: %50s Salt: %11s RefMD: %64s OpenSSLMD: %64s\n" "#$i" "$stat_raw" $mem "$input" "$salt" $ref $ossl >> log
done
done
done
done
