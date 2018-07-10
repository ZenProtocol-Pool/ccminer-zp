# allow to use Host cuda functions in C/C++
DEF_INCLUDES = @CUDA_INCLUDES@

if WANT_JANSSON
JANSSON_INCLUDES = -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES =
endif

EXTRA_DIST = autogen.sh README.txt LICENSE.txt \
			  cudaminer.sln cudaminer.vcxproj cudaminer.vcxproj.filters \
			  compat/gettimeofday.c compat/getopt/getopt_long.c cpuminer-config.h.in

SUBDIRS = compat

bin_PROGRAMS = ccminer

ccminer_SOURCES = elist.h miner.h compat.h \
			  compat/inttypes.h compat/stdbool.h compat/unistd.h \
			  compat/sys/time.h compat/getopt/getopt.h \
			  crc32.c \
			  util.cpp ccminer.cpp \
			  api.cpp hashlog.cpp stats.cpp sysinfos.cpp cuda.cpp \
			  nvml.cpp nvml.h nvsettings.cpp \
			  sph/simd.c sph/shavite.c cuda_checkhash.cu cuda_helper.h cuda_vector.h \
			  Algo256/cuda_keccak256.cu Algo256/zenprotocol.cu Algo256/keccak256.cu \
			  sph/keccak.c
		  
if HAVE_NVML
nvml_defs = -DUSE_WRAPNVML
nvml_libs = -ldl
endif

ccminer_LDFLAGS  = $(PTHREAD_FLAGS) @CUDA_LDFLAGS@
ccminer_LDADD    = @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @CUDA_LIBS@ @OPENMP_CFLAGS@ @LIBS@ $(nvml_libs)
ccminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ @OPENMP_CFLAGS@ $(CPPFLAGS) $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES) $(DEF_INCLUDES) $(nvml_defs)

if HAVE_OSX
ccminer_CPPFLAGS += -I/usr/local/llvm/lib/clang/4.0.0/include
ccminer_LDFLAGS += -L/usr/local/llvm/lib
ccminer_LDADD += -lomp
endif

nvcc_ARCH  = -gencode=arch=compute_61,code=sm_61
nvcc_ARCH += -gencode=arch=compute_60,code=sm_60
nvcc_ARCH += -gencode=arch=compute_52,code=sm_52
nvcc_ARCH += -gencode=arch=compute_50,code=sm_50
nvcc_ARCH += -gencode=arch=compute_37,code=sm_37
nvcc_ARCH += -gencode=arch=compute_35,code=sm_35
nvcc_ARCH += -gencode=arch=compute_30,code=sm_30
nvcc_ARCH += -gencode=arch=compute_70,code=sm_70

nvcc_FLAGS = $(nvcc_ARCH) @CUDA_INCLUDES@ -I. @CUDA_CFLAGS@
nvcc_FLAGS += $(JANSSON_INCLUDES)

# we're now targeting all major compute architectures within one binary.
.cu.o:
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=128 -o $@ -c $<


