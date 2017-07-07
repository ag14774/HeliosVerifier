# Yet Another Helios Verifier(YAHV)

The verifier is written in Python and requires a minimum version of *Python v3.6*. The modules ```tqdm```, ```requests``` and ```terminaltables``` are required to be installed. In addition, the ```gmpy2``` module can lead to significant performance improvements and therefore it is recommended that it is installed.

## Prerequisites
All modules can be installed with:
```bash
pip install requests tqdm terminaltables gmpy2
```

## Running the verifier
```bash
python verifier.py --uuid=33384bfc-50a7-11e4-a8e6-ee6ee3abb408 --path=./downloads/IACR2014 --cores=8
```
The full list of arguments is shown below:
* ```--help``` :Displays a help message
* ```--host``` :The address of the host of the election. This is optional and by default ```--host=https://vote.heliosvoting.org/helios```.
* ```--uuid``` :The unique election identifier.
* ```--path``` :The location where the election data should be stored.
* ```--force-download``` :When this argument is given, the election data will be re-downloaded from the server, even if path contains all the data.
* ```--cores``` :The number of cores to use during verification. This is an optional parameter and by default it is equal to the maximum number of cores available.
