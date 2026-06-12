import sys
import os
import pefile
import pandas as pd
import joblib


# Path del modello salvato dal notebook 03
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_best_model.pkl')


# ESTRAZIONE DELLE 77 FEATURE
def _section_stats(pe):
    """Calcola le statistiche aggregate sulle sezioni del file PE."""
    sections = pe.sections
    n = len(sections)
    if n == 0:
        zeros = [0] * 15
        return dict(zip([
            'SectionsLength', 'SectionMinEntropy', 'SectionMaxEntropy',
            'SectionMinRawsize', 'SectionMaxRawsize',
            'SectionMinVirtualsize', 'SectionMaxVirtualsize',
            'SectionMaxPhysical', 'SectionMinPhysical',
            'SectionMaxVirtual', 'SectionMinVirtual',
            'SectionMaxPointerData', 'SectionMinPointerData',
            'SectionMaxChar', 'SectionMainChar'
        ], zeros))

    entropies   = [s.get_entropy()                for s in sections]
    raw_sizes   = [s.SizeOfRawData                for s in sections]
    virt_sizes  = [s.Misc_VirtualSize             for s in sections]
    phys_addrs  = [s.PointerToRawData             for s in sections]
    virt_addrs  = [s.VirtualAddress               for s in sections]
    ptr_data    = [s.PointerToRawData             for s in sections]
    chars       = [s.Characteristics              for s in sections]

    return {
        'SectionsLength':         n,
        'SectionMinEntropy':      min(entropies),
        'SectionMaxEntropy':      max(entropies),
        'SectionMinRawsize':      min(raw_sizes),
        'SectionMaxRawsize':      max(raw_sizes),
        'SectionMinVirtualsize':  min(virt_sizes),
        'SectionMaxVirtualsize':  max(virt_sizes),
        'SectionMaxPhysical':     max(phys_addrs),
        'SectionMinPhysical':     min(phys_addrs),
        'SectionMaxVirtual':      max(virt_addrs),
        'SectionMinVirtual':      min(virt_addrs),
        'SectionMaxPointerData':  max(ptr_data),
        'SectionMinPointerData':  min(ptr_data),
        'SectionMaxChar':         max(chars),
        'SectionMainChar':        chars[0],   # caratteristiche della sezione principale
    }

# FUNZIONI DERIVATE BLACKLISTING
def _suspicious_imports(pe):
    SUSPICIOUS_DLLS = {
        'kernel32.dll', 'advapi32.dll', 'ntdll.dll', 'user32.dll',
        'ws2_32.dll', 'wininet.dll', 'urlmon.dll', 'shell32.dll'
    }
    SUSPICIOUS_FUNCS = {
        b'CreateRemoteThread', b'WriteProcessMemory', b'VirtualAllocEx',
        b'LoadLibraryA', b'GetProcAddress', b'WinExec', b'ShellExecuteA',
        b'URLDownloadToFileA', b'InternetOpenA',
    }
    count = 0
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors='ignore').lower()
        if dll in SUSPICIOUS_DLLS:
            for imp in entry.imports:
                if imp.name and imp.name in SUSPICIOUS_FUNCS:
                    count += 1
    return count


def _suspicious_section_names(pe):
    """Conta le sezioni con nome anomalo (es. UPX, .packed, nomi non standard)."""
    STANDARD = {
        '.text', '.data', '.rdata', '.bss', '.idata', '.edata',
        '.pdata', '.rsrc', '.reloc', '.tls', '.debug', '.crt', '.gfids'
    }
    count = 0
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode(errors='ignore').lower()
        if name and name not in STANDARD:
            count += 1
    return count


def extract_features(file_path):
    pe = pefile.PE(file_path, fast_load=False)

    feats = {}

    # DOS Header (17 feature)
    dos = pe.DOS_HEADER
    feats['e_magic']    = dos.e_magic
    feats['e_cblp']     = dos.e_cblp
    feats['e_cp']       = dos.e_cp
    feats['e_crlc']     = dos.e_crlc
    feats['e_cparhdr']  = dos.e_cparhdr
    feats['e_minalloc'] = dos.e_minalloc
    feats['e_maxalloc'] = dos.e_maxalloc
    feats['e_ss']       = dos.e_ss
    feats['e_sp']       = dos.e_sp
    feats['e_csum']     = dos.e_csum
    feats['e_ip']       = dos.e_ip
    feats['e_cs']       = dos.e_cs
    feats['e_lfarlc']   = dos.e_lfarlc
    feats['e_ovno']     = dos.e_ovno
    feats['e_oemid']    = dos.e_oemid
    feats['e_oeminfo']  = dos.e_oeminfo
    feats['e_lfanew']   = dos.e_lfanew

    # File Header (7 feature)
    fh = pe.FILE_HEADER
    feats['Machine']              = fh.Machine
    feats['NumberOfSections']     = fh.NumberOfSections
    feats['TimeDateStamp']        = fh.TimeDateStamp
    feats['PointerToSymbolTable'] = fh.PointerToSymbolTable
    feats['NumberOfSymbols']      = fh.NumberOfSymbols
    feats['SizeOfOptionalHeader'] = fh.SizeOfOptionalHeader
    feats['Characteristics']      = fh.Characteristics

    # Optional Header (28 feature)
    oh = pe.OPTIONAL_HEADER
    feats['Magic']                       = oh.Magic
    feats['MajorLinkerVersion']          = oh.MajorLinkerVersion
    feats['MinorLinkerVersion']          = oh.MinorLinkerVersion
    feats['SizeOfCode']                  = oh.SizeOfCode
    feats['SizeOfInitializedData']       = oh.SizeOfInitializedData
    feats['SizeOfUninitializedData']     = oh.SizeOfUninitializedData
    feats['AddressOfEntryPoint']         = oh.AddressOfEntryPoint
    feats['BaseOfCode']                  = oh.BaseOfCode
    feats['ImageBase']                   = oh.ImageBase
    feats['SectionAlignment']            = oh.SectionAlignment
    feats['FileAlignment']               = oh.FileAlignment
    feats['MajorOperatingSystemVersion'] = oh.MajorOperatingSystemVersion
    feats['MinorOperatingSystemVersion'] = oh.MinorOperatingSystemVersion
    feats['MajorImageVersion']           = oh.MajorImageVersion
    feats['MinorImageVersion']           = oh.MinorImageVersion
    feats['MajorSubsystemVersion']       = oh.MajorSubsystemVersion
    feats['MinorSubsystemVersion']       = oh.MinorSubsystemVersion
    feats['SizeOfHeaders']               = oh.SizeOfHeaders
    feats['CheckSum']                    = oh.CheckSum
    feats['SizeOfImage']                 = oh.SizeOfImage
    feats['Subsystem']                   = oh.Subsystem
    feats['DllCharacteristics']          = oh.DllCharacteristics
    feats['SizeOfStackReserve']          = oh.SizeOfStackReserve
    feats['SizeOfStackCommit']           = oh.SizeOfStackCommit
    feats['SizeOfHeapReserve']           = oh.SizeOfHeapReserve
    feats['SizeOfHeapCommit']            = oh.SizeOfHeapCommit
    feats['LoaderFlags']                 = oh.LoaderFlags
    feats['NumberOfRvaAndSizes']         = oh.NumberOfRvaAndSizes

    # Feature derivate (2)
    feats['SuspiciousImportFunctions'] = _suspicious_imports(pe)
    feats['SuspiciousNameSection']     = _suspicious_section_names(pe)

    # Statistiche sezioni (15 feature)
    feats.update(_section_stats(pe))

    # Data Directories (8 feature) 
    # Indici standard nel PE format:
    # 0=Export, 1=Import, 2=Resource, 3=Exception, 4=Security
    dd = oh.DATA_DIRECTORY
    feats['DirectoryEntryImport']         = dd[1].VirtualAddress
    feats['DirectoryEntryImportSize']     = dd[1].Size
    feats['DirectoryEntryExport']         = dd[0].VirtualAddress
    feats['ImageDirectoryEntryExport']    = dd[0].Size
    feats['ImageDirectoryEntryImport']    = dd[1].Size
    feats['ImageDirectoryEntryResource']  = dd[2].Size
    feats['ImageDirectoryEntryException'] = dd[3].Size
    feats['ImageDirectoryEntrySecurity']  = dd[4].Size

    pe.close()
    return feats

# MAIN
def main():
    if len(sys.argv) != 2:
        print(__doc__)
        print("\nERRORE: passare il percorso al file PE come unico argomento.")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"ERRORE: file non trovato: {file_path}")
        sys.exit(1)

    if not os.path.isfile(MODEL_PATH):
        print(f"ERRORE: modello non trovato in {MODEL_PATH}")
        print("Esegui prima il notebook 03_random_forest.ipynb per generarlo.")
        sys.exit(1)

    # Carica modello
    print(f"Carico modello: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)

    # Le 77 feature nell'ordine esatto del training (sklearn >= 1.0 lo memorizza)
    feature_order = list(model.feature_names_in_)

    # Estrai feature dal file
    print(f"Analizzo file: {file_path}")
    try:
        feats = extract_features(file_path)
    except pefile.PEFormatError as e:
        print(f"ERRORE: file non e' un PE valido. Dettagli: {e}")
        sys.exit(1)

    # Verifica completezza
    missing = [f for f in feature_order if f not in feats]
    if missing:
        print(f"ERRORE: feature mancanti dall'estrattore: {missing}")
        sys.exit(1)

    # Costruisci DataFrame con le colonne nell'ordine richiesto dal modello
    X = pd.DataFrame([feats])[feature_order]

    # Predici
    pred  = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    label = 'MALWARE' if pred == 1 else 'legitimate'
    confidence = proba[pred] * 100

    # Stampa risultato
    print()
    print('=' * 50)
    print(f"  File:        {os.path.basename(file_path)}")
    print(f"  Predizione:  {label}")
    print(f"  Confidenza:  {confidence:.2f}%")
    print(f"  P(legit):    {proba[0]*100:.2f}%")
    print(f"  P(malware):  {proba[1]*100:.2f}%")
    print('=' * 50)


if __name__ == '__main__':
    main()
