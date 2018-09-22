#!/bin/bash
# Original Live by cybojenix <anthonydking@gmail.com>
# New Live/Menu by Caio Oliveira aka Caio99BR <caiooliveirafarias0@gmail.com>
# Colors by Aidas Lukošius aka aidasaidas75 <aidaslukosius75@yahoo.com>
# Toolchains and support for msm8996 by JonasCardoso aka JonasCardoso <jonascard60@gmail.com>
# Rashed for the base of zip making
# And the internet for filling in else where

# You need to download https://bitbucket.org/jonascardoso/toolchain_aarch64
# Clone in the same folder as the kernel to choose a toolchain and not specify a location

# Main Process - Start
maindevice() {
#clear
echo "-${bldgrn}Device choice${txtrst}-"
echo
_name=${name}
_variant=${variant}
_defconfig=${defconfig}
unset name variant defconfig
clear
echo "0) ${bldred}Xiaomi Mi5${txtrst}       | Lite/Prime/Pro | Gemini"
echo
echo "1) ${bldyel}Xiaomi Mi5S${txtrst}      | Lite/Prime/Pro | Capricorn"
echo
echo "2) ${bldcya}Xiaomi Mi5S Plus${txtrst} | Prime/Pro      | Natrium"
echo
echo "3) ${bldgrn}Xiaomi Mi Mix${txtrst}    | Prime/Pro      | Lithium"
echo
echo "4) ${bldmag}Xiaomi Mi Note 2${txtrst} | Lite/Prime/Pro | Scorpio"
echo
echo "*) Any other key to Exit"
echo
read -p "Choice: " -n 1 -s x
case "${x}" in
	0 ) defconfig="gemini_defconfig"; name="Mi5"; variant="Lite-Prime-Pro"; name1="Mi 5"; name2="MI5"; name3="gemini"; name4="Gemini";;
	1 ) defconfig="capricorn_defconfig"; name="Mi5S"; variant="Lite-Prime-Pro"; name1="Mi 5s"; name2="MI5S"; name3="capricorn"; name4="Capricorn";;
	2 ) defconfig="natrium_defconfig"; name="Mi5SPlus"; variant="Prime-Pro"; name1="Mi 5 Plus"; name2="MI5SPlus"; name3="natrium"; name4="Natrium";;
	3 ) defconfig="lithium_defconfig"; name="MiMix"; variant="Prime-Pro"; name1="Mi Mix"; name2="MIMix"; name3="lithium"; name4="Lithium";;
	4 ) defconfig="scorpio_defconfig"; name="MiNote2"; variant="Lite-Prime-Pro"; name1="Mi Note 2"; name2="MINote2"; name3="scorpio"; name4="Scorpio";;
	* ) ;;
esac
if [ "${defconfig}" == "" ]
then
	name=${_name}
	variant=${_variant}
	defconfig=${_defconfig}
	unset _name _variant _defconfig
else
	make ${defconfig} &> /dev/null | echo "${x} - ${name} ${variant}, setting..."
	unset buildprocesscheck zippackagecheck defconfigcheck
fi
clear
}

maintoolchain() {
clear
echo "-Toolchain choice-"
echo
if [ -f ../Toolchain/aptess.sh ]
then
	. ../Toolchain/aptess.sh
else
	if [ -d ../Toolchain ]
	then
		echo "You not have APTESS Script in Android Prebuilt Toolchain folder"
		echo "Check the folder"
		echo "We will use Manual Method now"
	else
		echo "-You don't have Toolchains-"
	fi
	echo
	echo "Please specify a location"
	echo "and the prefix of the chosen toolchain at the end"
	echo "GCC 4.6 ex. ../arm-eabi-4.6/bin/arm-eabi-"
	echo
	echo "/home/jonas/Dev/android-toolchain-eabi/bin/arm-eabi-"
	echo "Stay blank if you want to exit"
	echo
	read -p "Place: " CROSS_COMPILE
	if ! [ "${CROSS_COMPILE}" == "" ]
	then
		ToolchainCompile="${CROSS_COMPILE}"
	fi
fi
if ! [ "${CROSS_COMPILE}" == "" ]
then
	unset buildprocesscheck zippackagecheck
fi
clear
}
# Main Process - End

# Build Process - Start
buildprocess() {
if [ -f .config ]
then
	echo "${x} - Building ${customkernel}"

	if [ -f arch/${ARCH}/boot/Image.gz-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.gz;
		rm -rf arch/${ARCH}/boot/Image.gz-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.lzma-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.lzma;
		rm -rf arch/${ARCH}/boot/Image.lzma-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.bz2-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.bz2;
		rm -rf arch/${ARCH}/boot/Image.bz2-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.xz-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.xz;
		rm -rf arch/${ARCH}/boot/Image.xz-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.lzo-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.lzo;
		rm -rf arch/${ARCH}/boot/Image.lzo-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.lz4-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.lz4;
		rm -rf arch/${ARCH}/boot/Image.lz4-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image ]
	then
		rm -rf arch/${ARCH}/boot/Image;
	fi

	NR_CPUS=$(($(grep -c ^processor /proc/cpuinfo) + 1))
	echo "${bldblu}Building ${customkernel} with ${NR_CPUS} jobs at once${txtrst}"

	START=$(date +"%s")
	if [ "${buildoutput}" == "OFF" ]
	then
		make -j${NR_CPUS} &>/dev/null | loop
	else
		make -j${NR_CPUS}
	fi

	END=$(date +"%s")
	BUILDTIME=$((${END} - ${START}))

	if [ -f arch/${ARCH}/boot/Image.gz-dtb ] || [ -f arch/${ARCH}/boot/Image.lzma-dtb ] || [ -f arch/${ARCH}/boot/Image.bz2-dtb ] || [ -f arch/${ARCH}/boot/Image.xz-dtb ] || [ -f arch/${ARCH}/boot/Image.lzo-dtb ] || [ -f arch/${ARCH}/boot/Image.lz4-dtb ]
	then
		buildprocesscheck="${_d}"
	else
		buildprocesscheck="Something goes wrong"
	fi
else
	ops
fi
}

loop() {
LEND=$(date +"%s")
LBUILDTIME=$((${LEND} - ${START}))
echo -ne "\r\033[K"
echo -ne "${bldgrn}Build Time: $((${LBUILDTIME} / 60)) minutes and $((${LBUILDTIME} % 60)) seconds.${txtrst}"
if [ -f arch/${ARCH}/boot/Image.gz-dtb ] || [ -f arch/${ARCH}/boot/Image.lzma-dtb ] || [ -f arch/${ARCH}/boot/Image.bz2-dtb ] || [ -f arch/${ARCH}/boot/Image.xz-dtb ] || [ -f arch/${ARCH}/boot/Image.lzo-dtb ] || [ -f arch/${ARCH}/boot/Image.lz4-dtb ]
then
	sleep 1
	loop
fi
}

updatedefconfig(){
if [ -f .config ]; then
#	clear
	echo "-${bldgrn}Updating defconfig${txtrst}-"
	echo
	if [ $(cat arch/${ARCH}/configs/${defconfig} | grep "Automatically" | wc -l) -ge 1 ]
	then
		defconfigformat="Usual copy of .config format  | Complete"
	else
		defconfigformat="Default Linux Kernel format   | Small"
	fi
	echo "The actual defconfig is a:"
	echo "--${defconfigformat}--"
	echo
	echo "Update defconfig to:"
	echo "1) Default Linux Kernel format  | Small"
	echo "2) Usual copy of .config format | Complete"
	echo
	echo "*) Any other key to Exit"
	echo
	read -p "Choice: " -n 1 -s x
	case "${x}" in
		1 ) echo "Building..."; make savedefconfig &>/dev/null; mv defconfig arch/${ARCH}/configs/${defconfig};;
		2 ) cp .config arch/${ARCH}/configs/${defconfig};;
		* ) ;;
	esac
else
	ops
fi
}
# Build Process - End

# Zip Process - Start
zippackage() {
if ! [ "${defconfig}" == "" ]
then
if [ -f arch/${ARCH}/boot/Image.gz ] || [ -f arch/${ARCH}/boot/Image.lzma ] || [ -f arch/${ARCH}/boot/Image.bz2 ] || [ -f arch/${ARCH}/boot/Image.xz ] || [ -f arch/${ARCH}/boot/Image.lzo ] || [ -f arch/${ARCH}/boot/Image.lz4 ]
	then
		echo "${x} - Ziping ${customkernel}"

		zipdirout="zip-creator-out"
		rm -rf ${zipdirout}
		mkdir ${zipdirout}

		cp -r zip-creator/base/* ${zipdirout}/

		if [ "${compressedimage}" == "${bldyel}ON${txtrst}" ];
		then

			if [ -f arch/${ARCH}/boot/Image.gz-dtb ]; then
				cp arch/${ARCH}/boot/Image.gz-dtb ${zipdirout}/zImage

			elif [ -f arch/${ARCH}/boot/Image.lzma-dtb ]; then
				cp arch/${ARCH}/boot/Image.lzma-dtb ${zipdirout}/zImage

			elif [ -f arch/${ARCH}/boot/Image.bz2-dtb ]; then
				cp arch/${ARCH}/boot/Image.bz2-dtb ${zipdirout}/zImage

			elif [ -f arch/${ARCH}/boot/Image.xz-dtb ]; then
				cp arch/${ARCH}/boot/Image.xz-dtb ${zipdirout}/zImage

			elif [ -f arch/${ARCH}/boot/Image.lzo-dtb ]; then
				cp arch/${ARCH}/boot/Image.lzo-dtb ${zipdirout}/zImage

			elif [ -f arch/${ARCH}/boot/Image.lz4-dtb ]; then
				cp arch/${ARCH}/boot/Image.lz4-dtb ${zipdirout}/zImage

			fi

		else
			cp arch/${ARCH}/boot/Image ${zipdirout}/zImage
	
		fi

		echo "maintainer=${maintainer}" >> ${zipdirout}/device.prop
		echo "customkernel=${customkernel}" >> ${zipdirout}/device.prop
		echo "name=${name}" >> ${zipdirout}/device.prop
		echo "variant=${variant}" >> ${zipdirout}/device.prop
		echo "release=${release}" >> ${zipdirout}/device.prop
		echo "releasewithbar=${releasewithbar}" >> ${zipdirout}/device.prop
		echo "ToolchainName=${ToolchainName}" >> ${zipdirout}/device.prop
		echo "romversion=${romversion}" >> ${zipdirout}/device.prop
		echo "androidversion=${androidversion}" >> ${zipdirout}/device.prop
		echo "name1=${name1}" >> ${zipdirout}/device.prop
		echo "name2=${name2}" >> ${zipdirout}/device.prop
		echo "name3=${name3}" >> ${zipdirout}/device.prop
		echo "name4=${name4}" >> ${zipdirout}/device.prop

		mkdir ${zipdirout}/modules
		mkdir ${zipdirout}/qca_cld
		find . -name *.ko | xargs cp -a --target-directory=${zipdirout}/modules/ &> /dev/null
		find . -name wlan.ko | xargs cp -a --target-directory=${zipdirout}/qca_cld/ &> /dev/null
        cp ${zipdirout}/qca_cld/wlan.ko ${zipdirout}/qca_cld/qca_cld_wlan.ko
		rm -rf ${zipdirout}/modules/wlan.ko
		rm -rf ${zipdirout}/qca_cld/wlan.ko
		${CROSS_COMPILE}strip --strip-unneeded ${zipdirout}/modules/*.ko
		${CROSS_COMPILE}strip --strip-unneeded ${zipdirout}/qca_cld/*.ko


		cd ${zipdirout}
		zip -r ${zipfile} * -x .gitignore &> /dev/null
		cd ..

		cp ${zipdirout}/${zipfile} zip-creator/
		rm -rf ${zipdirout}

		zippackagecheck="${_d}"
	else
		ops
	fi
else
	ops
fi
clear
}
# Zip Process - End

# ADB - Start
adbcopy() {
if [ -f zip-creator/${zipfile} ]; then
	clear
	echo "-Coping ${customkernel}-"
	echo
	echo "You want to copy:"
	echo
	echo "a) For Internal Card (sdcard0)"
	echo "b) For External Card (sdcard1)"
	echo "c) For Internal Card Emulated (/emulated/0)"
	echo "d) For Data Media (/data/media)"
	echo
	echo "*) Any other key for exit"
	echo
	read -p "Choice: " -n 1 -s x
	case "$x" in
		a ) echo "Coping to Internal Card..."; _ac="sdcard0" ;;
		b ) echo "Coping to External Card..."; _ac="sdcard1" ;;
		c ) echo "Coping to Internal Card Emulated..."; _ac="emulated/0" ;;
		d ) echo "Coping to Data Media..."; _ac="data/media" ;;
		* ) ;;
	esac
	if ! [ ${_ac} == "" ]
	then
		adb shell rm -rf /storage/${_ac}/${zipfile} &> /dev/null
		adb push zip-creator/${zipfile} /storage/${_ac}/${zipfile} &> /dev/null
		unset _ac
	fi
else
	ops
fi
clear
}
# ADB - End

# Menu - Start
buildsh() {
#clear
echo ""
echo "-${bldcya}Basic Info${txtrst}-"
echo "Custom Linux Kernel ${kernelversion}.${kernelpatchlevel}.${kernelsublevel} for ${manufacturer} ${soc} devices"
echo "${customkernel}-${androidversion}-${romversion} Release $(date +%d"/"%m"/"%Y) Build #${build}"
echo "-${bldred}Clean Menu${txtrst}-"
echo "1) Zip Packages      | ${bldred}${cleanzipcheck}${txtrst}"
echo "2) Kernel            | ${bldred}${cleankernelcheck}${txtrst}"
echo "-${bldgrn}Main Menu${txtrst}-"
echo "3) Device Choice     | ${bldgrn}${name} ${variant}${txtrst}"
echo "4) Toolchain Choice  | ${bldgrn}${ToolchainCompile}${txtrst}"
echo "-${bldyel}Build Menu${txtrst}-"
echo "5) Build Kernel      | ${bldyel}${buildprocesscheck}${txtrst}"
if ! [ "${BUILDTIME}" == "" ]
then
	echo "   Build Time        | ${bldcya}$((${BUILDTIME} / 60))m$((${BUILDTIME} % 60))s${txtrst}"
fi
echo "6) Build Zip Package | ${bldyel}$zippackagecheck${txtrst}"
if [ -f zip-creator/${zipfile} ]
then
	echo "   Zip Saved         | ${bldcya}zip-creator/${zipfile}${txtrst}"
fi
echo "7) Compressed image  | ${compressedimage}"
echo "-${bldblu}Special Device Menu${txtrst}-"
echo "8) Update Defconfig  | ${bldblu}${defconfigcheck}${txtrst}"
echo "9) Copy Zip          | ${bldblu}${zipcopycheck}${txtrst}"
echo "0) Reboot to recovery"
echo "-${bldmag}Script Options${txtrst}-"
echo "o) View Build Output | ${buildoutput}"
echo "g) Git Gui  |  k) GitK  |  s) Git Push  |  l) Git Pull"
echo "q) Quit"
echo
read -n 1 -p "${txtbld}Choice: ${txtrst}" -s x
case ${x} in
	1) echo "${x} - Cleaning Zips"; rm -rf zip-creator/*.zip; unset zippackagecheck;clear;;
	2) echo "${x} - Cleaning Kernel"; make clean mrproper &> /dev/null;

	if [ -f arch/${ARCH}/boot/Image.gz-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.gz;
		rm -rf arch/${ARCH}/boot/Image.gz-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.lzma-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.lzma;
		rm -rf arch/${ARCH}/boot/Image.lzma-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.bz2-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.bz2;
		rm -rf arch/${ARCH}/boot/Image.bz2-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.xz-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.xz;
		rm -rf arch/${ARCH}/boot/Image.xz-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.lzo-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.lzo;
		rm -rf arch/${ARCH}/boot/Image.lzo-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image.lz4-dtb ]
	then
		rm -rf arch/${ARCH}/boot/Image.lz4;
		rm -rf arch/${ARCH}/boot/Image.lz4-dtb;
	fi

	if [ -f arch/${ARCH}/boot/Image ]
	then
		rm -rf arch/${ARCH}/boot/Image;
	fi

	unset buildprocesscheck name variant defconfig BUILDTIME;clear;;

	3) maindevice;;
	4) maintoolchain;;
	5) buildprocess;;
	6) zippackage;;
	7)
	
	if [ "${compressedimage}" == "${bldyel}ON${txtrst}" ]; 
	then compressedimage="${bldred}OFF${txtrst}"
	else compressedimage="${bldyel}ON${txtrst}";fi;;

	8) updatedefconfig;;
	9) adbcopy;;
	0) echo "${x} - Rebooting to Recovery..."; adb reboot recovery;;
	o) if [ "${buildoutput}" == "OFF" ]; then unset buildoutput; else buildoutput="OFF"; fi;;
	q) echo "${x} - Ok, Bye!"; break;;
	g) echo "${x} - Opening Git Gui"; git gui;;
	k) echo "${x} - Opening GitK"; gitk;;
	s) echo "${x} - Pushing to remote repo"; git push --verbose --all; sleep 3;;
	l) echo "${x} - Pushing to local repo"; git pull --verbose --all; sleep 3;;
	*) ops;;
esac
}

# Menu - End

# The core of script is here!

ops() {
echo "${x} - This option is not valid"; sleep 1
}

if [ ! "${BASH_VERSION}" ]
	then echo "Please do not use sh to run this script, just use . build.sh"
elif [ -e build.sh ]; then
	# Stock Color
	txtrst=$(tput sgr0)
	# Bold Colors
	txtbld=$(tput bold) # Bold
	bldred=${txtbld}$(tput setaf 1) # red
	bldgrn=${txtbld}$(tput setaf 2) # green
	bldyel=${txtbld}$(tput setaf 3) # yellow
	bldblu=${txtbld}$(tput setaf 4) # blue
	bldmag=${txtbld}$(tput setaf 5) # magenta
	bldcya=${txtbld}$(tput setaf 6) # cyan
	bldwhi=${txtbld}$(tput setaf 7) # white
	# Common Messages
	_d="Already Done!"
	_r="Ready to do!"
	# Main Variables
    manufacturer=Xiaomi
    soc=MSM8996/PRO
	maintainer=JonasCardoso
	customkernel=FloppyKernel
	romversion=MIUI
	androidversion=Oreo
	export ARCH=arm64

	while true
	do
		if [ "${buildoutput}" == "" ]
		then
			buildoutput="${bldmag}ON${txtrst}"
		fi

		if [ "${compressedimage}" == "" ]
		then
			compressedimage="${bldyel}ON${txtrst}"
		fi

		if [ "${zippackagecheck}" == "${_d}" ]
		then
			zipcopycheck="${_r}"
		else
			zipcopycheck="Use 6 first"
		fi
		if [ "${buildprocesscheck}" == "" ]
		then
			buildprocesscheck="${_r}"
			zippackagecheck="Use 5 first"
		fi
		if [ "${buildprocesscheck}" == "${_d}" ]
		then
			if ! [ "$zippackagecheck" == "${_d}" ]
			then
				zippackagecheck="${_r}"
			fi
		fi
		if [ "${CROSS_COMPILE}" == "" ]
		then
			buildprocesscheck="Use 4 first"
		fi
		if [ "${defconfig}" == "" ]
		then
			buildprocesscheck="Use 3 first"
			defconfigcheck="Use 3 first"
		else
			defconfigcheck="${_r}"
		fi
		if [ -f zip-creator/*.zip ]
		then
			unset cleanzipcheck
		else
			cleanzipcheck="${_d}"
		fi
		if [ -f .config ]
		then
			unset cleankernelcheck
		else
			cleankernelcheck="${_d}"
		fi
		if ! [ -f .version ]
		then
			echo "0" > .version
		fi
		kernelversion=$(cat Makefile | grep VERSION | cut -c 11- | head -1)
		kernelpatchlevel=$(cat Makefile | grep PATCHLEVEL | cut -c 14- | head -1)
		kernelsublevel=$(cat Makefile | grep SUBLEVEL | cut -c 12- | head -1)
		kernelname=$(cat Makefile | grep NAME | cut -c 8- | head -1)
		release=$(date +%d""%m""%Y)
		releasewithbar=$(date +%d"/"%m"/"%Y)
		build=$(cat .version)
		export zipfile="${customkernel}-${name}-${variant}-${release}-${ToolchainName}-${androidversion}-${romversion}.zip"
		buildsh
	done
else
	echo
	echo "Ensure you run this file from the SAME folder as where it was,"
	echo "otherwise the script will have problems running the commands."
	echo "After you 'cd' to the correct folder, start the build script"
	echo "with the . build.sh command, NOT with any other command!"
	echo
fi
