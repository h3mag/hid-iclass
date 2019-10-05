# hid-iclass

Python script to diversify HID iClass standard keys.

## Dependencies

- PyCrypto

	```
	pip install pycrypto
	```

## Usage

You must have previously dumped the HID iClass master key. By default, the script will look in the same folder for a file named `masterkey.hex`. You can specify a specific file path by using the `-m / --masterkey` argument.

```
usage: hid-iclass.py [-h] [-m MASTERKEY_FILE] CSN

positional arguments:
  CSN                   HID iClass card serial number (CSN)

optional arguments:
  -h, --help            show this help message and exit
  -m MASTERKEY_FILE, --masterkey MASTERKEY_FILE
                        path to dumped master key file (default: masterkey.hex)
```

## References

- https://www.openpcd.org/dl/HID-iCLASS-security.pdf
- https://www.cs.bham.ac.uk/~garciaf/publications/dismantling.iClass.pdf
