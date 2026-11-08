import "pe"

rule UPX_Packed_Section_Names
{
    meta:
        description = "PE file with UPX section names (packed with UPX)"
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.sections : (s.name == "UPX0" or s.name == "UPX1")
}