use ExtUtils::MakeMaker;

WriteMakefile(
    'dist'	=> {
	            PREOP	=> 'pod2text RSAkey.pm | tee README > $(DISTVNAME)/README; chmod -R u=rwX,go=rX . ; chown -R root.root .',
	            COMPRESS	=> 'gzip -9v',
	            SUFFIX	=> '.gz',
	           },
    'NAME'		=> 'OpenSSL::RSAkey',
    'VERSION_FROM'	=> 'RSAkey.pm',
    'LIBS'		=> [ "-lssl" ],
    'INC'		=> "-I.",
    'DEFINE'		=> '-DNO_BIO=1 -DNO_FP_API=1',
    'OBJECT'           =>  'mt19937int.o RSAkey.o',
    'PM'		=> { 'RSAkey.pm' => '$(INST_LIBDIR)/RSAkey.pm',
   			     'SMS.pm' => '$(INST_LIBDIR)/RSAkey/SMS.pm', 
                             'XMLKeys.pm' => '$(INST_LIBDIR)/RSAkey/XMLKeys.pm', 
    },
    'PREREQ_PM' => {
    			XML::Parser => 2.27,
                   },
);
