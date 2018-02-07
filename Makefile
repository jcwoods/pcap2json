BUILDER_HOME=$(shell readlink -f $(HOME)/.builder)

SOURCES=pcap2json.c
TARGET=pcap2json

EXTRA_CPPFLAGS=-O2

include $(BUILDER_HOME)/executable.mk
