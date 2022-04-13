# krossock
C Socket (and ssl) wrapper library; for making the connecting to the internets a little easier.

***Cross compilation to Windows not fully supported yet***

## Library requirements
*(make sure you have these built for and installed on your toolchain)*
* openssl ( link with "-lssl -lcrypto" )

>*If you're using Arch and compiling for windows using mingw-w64, you may find
the following packages useful:*
>* *mingw-w64-openssl <sup>[AUR](https://aur.archlinux.org/packages/mingw-w64-openssl)</sup>*

## Additional Information
This appliction is set up to be built using autotools. You may use
`autoreconf --install` to produce `./configure`. It's a good idea to use
`./configure` in a `build/` subdirectory or outside of the build tree.

Feel free to propose changes to the functionality or documentation of this
application.

