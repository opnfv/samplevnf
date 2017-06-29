folder_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13 ; echo '');

git clone $1 $folder_name 2> /dev/null
if [ "$?" -ne "0" ]; then
    echo 0;
    exit 1;
fi
cd $folder_name;
(git ls-files | xargs cat | wc -l) 2> /dev/null;
cd ../;
rm -rf $folder_name;
