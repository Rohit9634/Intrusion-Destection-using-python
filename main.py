import pefile
import pandas as pd

def extract_exe_metadata(file_path):
    try:
        pe = pefile.PE(file_path)
        a = str(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        b = str(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        c = str(pe.OPTIONAL_HEADER.MajorImageVersion)
        d = str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        e = str(pe.OPTIONAL_HEADER.DllCharacteristics)
        f = str(pe.OPTIONAL_HEADER.SizeOfStackReserve)
        g = str(pe.FILE_HEADER.NumberOfSections)
        h = str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)

        data = [a, b, c, d, e, f, g, h]
        int_list = [int(x) for x in data]
        # print(int_list)
    except Exception as e:
        print(f"Error: {e}")
    return int_list
"""
def fetch_data():
    data = read_csv('data-set/MalwareDataSet.csv')
    data.shape
    data.describe()
    data.groupby(data['legitimate']).size()

    features = data.iloc[:, [0, 1, 2, 3, 4, 5, 6, 7]].values
    ifMalware = data.iloc[:, 8].values
"""
if __name__ == "__main__":
    file_path = "malwares/AnyDesk.exe"
    ex = extract_exe_metadata(file_path)
    data = pd.read_csv('dataset.csv')
    data.shape
    data.describe()
    # data.groupby(data['legitimate']).size()

    features = data.iloc[:, [0, 1, 2, 3, 4, 5, 6, 7]].values
    ifMalware = data.iloc[:, 8].values
    for x, z in zip(features, ifMalware):
        if all(i == j for i, j in zip(x, ex)):
            if(z == 1):
                print("It is a malware LOL :(")
            else:
                print("Not a malware")
