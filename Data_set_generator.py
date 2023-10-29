import pefile
import csv
import glob

malware = glob.glob('malwares/*.exe')
secure = glob.glob('secure/*.exe')

header = ["AddressOfEntryPoint", "MajorLinkerVersion", "MajorImageVersion", "MajorOperatingSystemVersion", "DllCharacteristics", "SizeOfStackReserve", "NumberOfSections", "ResourceSize", "IfMalware"]

with open('dataset.csv', 'w', encoding='UTF-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)

    # We added the pe information for Malware folder:

    for file in malware:
        pe = pefile.PE(file)
        a = str(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        b = str(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        c = str(pe.OPTIONAL_HEADER.MajorImageVersion)
        d = str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        e = str(pe.OPTIONAL_HEADER.DllCharacteristics)
        f = str(pe.OPTIONAL_HEADER.SizeOfStackReserve)
        g = str(pe.FILE_HEADER.NumberOfSections)
        h = str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)
        i = "1"

        data = [a, b, c, d, e, f, g, h, i]
        writer.writerow(data)

    # We added the pe information for safe software folder:

    for file in secure:
        pe = pefile.PE(file)
        a = str(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        b = str(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        c = str(pe.OPTIONAL_HEADER.MajorImageVersion)
        d = str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        e = str(pe.OPTIONAL_HEADER.DllCharacteristics)
        f = str(pe.OPTIONAL_HEADER.SizeOfStackReserve)
        g = str(pe.FILE_HEADER.NumberOfSections)
        h = str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)
        i = "0"

        data = [a, b, c, d, e, f, g, h, i]
        writer.writerow(data)

    # Close the CSV file
    # f.close()
