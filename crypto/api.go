package crypto

func FIPSMode(mode ...int) int {

	if len(mode) > 0 {
		FIPS_mode_set(mode[0])
	}
	return FIPS_mode()

}
