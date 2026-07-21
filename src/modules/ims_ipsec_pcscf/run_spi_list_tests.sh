#!/bin/sh

# build tests
gcc -D_IPSEC_SPI_LIST_TEST -I../../ -o spi_list_tests spi_list.c spi_list_tests.c ipsec_alg.c sec_agree.c cmd.c ipsec.c ipsec_evt.c -lmnl
# run tests
./spi_list_tests
