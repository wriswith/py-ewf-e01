# py-ewf-e01

## Description
This is a project to read and write Encase (ewf-e01) images without using C-libraries. This project can be used when working with images to avoid first converting to or from raw DD images.

## Usage
The main functions in ewf_reader.py and ewf_writer.py can be used to convert between DD and E01. Using pyinstaller the code can be made portable in an executable file. 

## Roadmap
The following functionality need to be added to be compatible with most forensic programs:
* Support for segmented images

The following functionalities would be useful:
* Support for STD-IN / STD-OUT
* NTFS-level compression
