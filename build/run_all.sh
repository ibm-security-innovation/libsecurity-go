#!/bin/bash

pushd .
cd ..

code=(
   "accounts" "acl" "entity" "ocra" "otp" "password" "salt" "storage" "setup"
   "restful/accounts-restful" "restful/entity-restful" "restful/libsecurity-restful" "restful/ocra-restful" "restful/otp-restful" "restful/password-restful" "restful/storage-restful" "restful/acl-restful"
   "app/token"
)

c1=`pwd`
mkdir res >& /dev/null
cpwd=$c1/res

rm -f $cpwd/res
rm -f $cpwd/full-res
rm -f $cpwd/tmp-res
for c in "${code[@]}" 
do
   echo "running tests of" $c >> $cpwd/tmp-res
   echo ""
   echo "Test" $c
   pushd . >& /dev/null
   cd $c

   if [ $c == "setup" ]
   then
      ./generate.sh
   else
      go test -cover | tee -a $cpwd/tmp-res
      go build github.com/ibm-security-innovation/libsecurity-go/$c
      go install github.com/ibm-security-innovation/libsecurity-go/$c
   fi
   popd >& /dev/null
done

pushd . >& /dev/null
echo "Test code format"  >> $cpwd/tmp-res
echo "Test code format"
go vet github.com/ibm-security-innovation/libsecurity-go/... |& grep -v "go-restful" | grep -v "exit status" | tee -a $cpwd/tmp-res

echo "Test coding conventions"  >> $cpwd/tmp-res
echo "Test coding conventions"
golint github.com/ibm-security-innovation/libsecurity-go/... | tee -a $cpwd/tmp-res

popd >& /dev/null

grep -iw 'pass\|fail\|running\|error\|_examples\|.*.go:.*' < $cpwd/tmp-res >> $cpwd/res
cat $cpwd/tmp-res >> $cpwd/full-res

popd
