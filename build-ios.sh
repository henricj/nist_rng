#!/bin/bash

mkdir buildios
cd buildios

mkdir device
cd device
cmake -G 'Xcode' -DIOS=ON -DCMAKE_BUILD_TYPE=Release ../../
xcodebuild -target install -configuration Release
cd ..

mkdir sim
cd sim
cmake -G 'Xcode' -DIOS=sim -DCMAKE_BUILD_TYPE=Release ../../
xcodebuild -target install -configuration Release
cd ..

lipo -create -output libnist_rng.a device/lib/Release-iphoneos/libnist_rng.a sim/lib/Release-iphonesimulator/libnist_rng.a

cd ..
