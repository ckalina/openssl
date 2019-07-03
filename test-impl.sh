hash_ref() {
	echo -n $1 \
	| ./argon2-ref "salty much;padding:w" -$2 -t 3 -m 3 -p 1 -l 64 \
	| grep '^Hash:' | awk '{print $2;}'
}

hash_openssl() {
	./main $1 | tail -n 1
}

for type in d i id; do
make CFLAGS=-DARGON2$(echo $type | tr '[:lower:]' '[:upper:]') OPENSSL_LIB="./openssl-devel"
for i in `seq 1 10000`; do
for input in `head -n 1 /dev/urandom | base64 | head -n 1`; do
	input=${input:0:50}
	ref=`hash_ref $input $type`
	ossl=`hash_openssl $input $type`
	stat=`bash -c "diff <(echo $ref) <(echo $ossl) &> /dev/null && echo -e \"\e[32mMATCH\e[39m\" || echo -e \"\e[31mFAIL\e[39m\""`
	printf "[%4s Argon2$type\t%s]\tInput: %50s RefMD: %64s OpenSSLMD: %64s\n" "#$i" "$stat" "$input" $ref $ossl
done
done
done
