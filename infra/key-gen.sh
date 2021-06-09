export SECRET="owner word vocal dose decline sunset battle example forget excite gentle waste"

for i in 1 2; do for j in stash controller; do subkey inspect "$SECRET//$i//$j"; done; done
echo "BABE Keys"
for i in 1 2; do for j in babe; do subkey inspect "$SECRET//$i//$j" --scheme sr25519; done; done
echo "Grandpa Keys"
for i in 1 2; do for j in grandpa; do subkey inspect "$SECRET//$i//$j" --scheme sr25519; done; done
echo "Im Online Keys"
for i in 1 2; do for j in im_online; do subkey inspect "$SECRET//$i//$j" --scheme sr25519; done; done
echo "Authority Discovery Keys"
for i in 1 2; do for j in authority_discovery; do subkey inspect "$SECRET//$i//$j" --scheme sr25519; done; done