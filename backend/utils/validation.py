def is_valid_pcap(file):
    """Valida si un archivo es un PCAP legítimo revisando los primeros 4 bytes."""
    
    magic_numbers_pcap = [(0xA1, 0xB2, 0xC3, 0xD4), (0xD4, 0xC3, 0xB2, 0xA1)]  # PCAP
    magic_numbers_pcapng = [(0x0A, 0x0D, 0x0D, 0x0A)]  # PCAPNG

    try:
        with file.stream as f:
            magic = tuple(f.read(4))
            if magic in magic_numbers_pcap:
                return True
            elif magic in magic_numbers_pcapng:
                return True 
            else:
                return False
    except Exception as e:
        print(f"Error al validar archivo: {e}")
        return False