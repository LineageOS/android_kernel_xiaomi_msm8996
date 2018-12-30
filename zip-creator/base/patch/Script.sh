#!/sbin/sh

console=$(cat /tmp/console)
[ "$console" ] || console=/proc/$$/fd/1

print() {
	if [ "$1" ]; then
		echo "ui_print - $1" > "$console"
	else
		echo "ui_print  " > "$console"
	fi
	echo
}

abort() {
	[ "$1" ] && {
		print "Error: $1!"
		print "Aborting..."
	}
	exit 1
}

# replace_file <old file> <new file> (preserving metadata)
# replace a file, preserving metadata (using cat)
replace_file() {
	cat "$2" > "$1" || return
	rm -f "$2"
}

[ -f "$temp/default.prop" ]

# set a prop value in default.prop
# setprop <prop> <value>
setprop() {
	$found_prop || return
	if grep -q "^[[:space:]]*$1[[:space:]]*=" "$temp/default.prop"; then
		sed -i "s/^[[:space:]]*$1[[:space:]]*=.*$/$1=$2/g" "$temp/default.prop"
	else
		echo "$1=$2" >> "$temp/default.prop"
	fi
}

print "" && print "Script: 010-no-dm-verity.sh"
dmverity=false

if [ "$dmverity" = true ] ; then
{
	. "$env"
	temp=/tmp/anykernel/ramdis
	print "Disabling dm-verity in the fstab..."
	found_fstab=false

	for fstab in fstab.qcom; do
		[ -f $temp/$fstab ] || continue
		print "Found fstab: $fstab"
		awk '
			$1 ~ /^\// {
				n = split($5, flags, ",")
				newflags=""
				for (i = 1; i <= n; i++) {
					if (flags[i] == "")
						continue
					if (flags[i] ~ /^verify/)
						continue
					if (flags[i] ~ /^support_scfs/)
						continue
					if (i > 1) newflags = newflags ","
					newflags = newflags flags[i]
				}
				if ($5 != newflags) $5 = newflags
				if ($5 == "") $5 = "defaults"
			}
			{ print }
		' "$temp/$fstab" > "$temp/$fstab-"
		replace_file "$temp/$fstab" "$temp/$fstab-"
		found_fstab=true
		setprop ro.config.dmverity false
		rm -f verity_key sbin/firmware_key.cer
		print "Script finished"
	done

	$found_fstab || print "Unable to find the fstab!"

}
else
{
	print "Script disabled by default"
}
fi

print "" && print "Script: 015-selinux-permissive.sh"
selinux=true
if [ "$selinux" = true ] ; then
{
	temp=/tmp/anykernel/split_img
	found_cmdline=false

	for cmdline in boot.img-cmdline; do
		[ -f $temp/$cmdline ] || continue
		print "Found cmdline: $cmdline" && print "Setting SELinux to Permissive..."
        echo "androidboot.hardware=qcom ehci-hcd.park=3 lpm_levels.sleep_disabled=1 cma=32M@0-0xffffffff androidboot.selinux=permissive buildvariant=userdebug" >> $temp/boot.img-cmdline-new
		cat $temp/boot.img-cmdline-new > $temp/$cmdline	
        rm -rf $temp/boot.img-cmdline-new 
		found_cmdline=true
		print "Script finished"
	done

	$found_cmdline || print "Unable to find the boot.img-cmdline!"
	
}

else
{
	print "Script disabled by default"
}
fi

exit 0
