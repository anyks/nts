Name:         @name@
Version:      @version@
Release:      @release_number@
Summary:      @summary@
License:      LicenseRef-A-NTS-1.0
BuildArch:    @architecture@
Group:        Development/Libraries
URL:          @url@
Distribution: @distribution@

# The CMake build requirement
BuildRequires: cmake

# The build directory of the package
%define _rpmdir @prefix@

# Disable the RPATH check
%global __brp_check_rpaths %{nil}

# ALT Linux branch of the spec
%if "%_vendor" == "alt"

# Disable the ELF dependency check
%set_verify_elf_method none

# Disable the dependency discovery
%define __find_requires %{nil}

%endif

%description
@description@

%install
# Create the buildroot: ALT rpm removes it and does not recreate, while
# Fedora and openSUSE pre-create it; cp alone lands differently there
mkdir -p "%{buildroot}"
# Copy the whole anyks ecosystem layout: headers, both libraries,
# cmake files with the search link and the license text
cp -a "@stage@/usr" "%{buildroot}/"

%clean
cp $(find @prefix@ -name "@name@*.rpm") %{buildroot}/../
%if "%{noclean}" == ""
   rm -rf %{buildroot}
%endif

%files
%defattr(-,root,root)
/usr/include/anyks/@name@
/usr/lib/anyks/lib@name@.a
/usr/lib/anyks/lib@name@.so
/usr/lib/anyks/lib@name@.so.*
/usr/lib/cmake/anyks/@name@
/usr/lib/cmake/@name@
# ALT Linux rpm has no %license directive: there %license is a macro holding
# the License tag value, and the line "%license file" turns into a path
# "LicenseRef-A-NTS-1.0 file"
%if "%_vendor" == "alt"
%doc /usr/share/licenses/@name@/LICENSE
%else
%license /usr/share/licenses/@name@/LICENSE
%endif

%post
# Register the anyks ecosystem library directory at the loader
if [ ! -f /etc/ld.so.conf.d/anyks-@name@.conf ]; then
	echo "/usr/lib/anyks" > /etc/ld.so.conf.d/anyks-@name@.conf
fi

# Refresh the dynamic loader cache
ldconfig

%postun
# Remove the loader record on the complete removal of the package
if [ "$1" = "0" ]; then
	rm -f /etc/ld.so.conf.d/anyks-@name@.conf
fi

# Refresh the dynamic loader cache
ldconfig

%changelog
* @date@ @distribution@ <@email@> - @version@-@release_number@
- NTS version v@version@-@release_number@ release
