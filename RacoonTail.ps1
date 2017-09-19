##########################################
#                                        #
#           Racoon Tail                  #
#       Created by Rachel Moore          #
#            10/08/2017                  #
#                                        #
##########################################

[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null

$inputXML = @"
<Window x:Name="RacoonsTool" x:Class="WpfApplication2.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApplication2"
        mc:Ignorable="d"
        Title="Racoon Tail" Height="358.502" Width="540.587">
    <Window.Resources>
        <Color x:Key="Default">#FFE5E5E5</Color>
    </Window.Resources>
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="53*"/>
            <ColumnDefinition Width="202*"/>
            <ColumnDefinition Width="262*"/>
        </Grid.ColumnDefinitions>
        <TabControl x:Name="tabControl" Grid.ColumnSpan="3">
            <TabItem x:Name="UserInfo" Header="User Info" Margin="0,0,-8,0">
                <Grid Background="#FFCFCFCF">
                    <Grid HorizontalAlignment="Left" Width="507" Grid.ColumnSpan="2">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="31*"/>
                            <ColumnDefinition Width="138*"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock x:Name="textBlock" HorizontalAlignment="Left" Margin="44,13,0,0" TextWrapping="Wrap" Text="User ID" VerticalAlignment="Top"/>
                        <TextBox x:Name="UserID" HorizontalAlignment="Left" Height="23" Margin="26,34,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="85" Grid.ColumnSpan="2"/>
                        <Button x:Name="GetGroups" Content="Get Groups" HorizontalAlignment="Left" Margin="211.675,74,0,0" VerticalAlignment="Top" Width="75" RenderTransformOrigin="0.254,0.342" Grid.Column="1" ToolTip="List users AD groups"/>
                        <TextBox x:Name="UserData" HorizontalAlignment="Left" Height="134" Margin="26,116,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="468" Grid.ColumnSpan="2"/>
                        <Button x:Name="AccStatus" Content="Account Status" HorizontalAlignment="Left" Margin="239.675,35,0,0" VerticalAlignment="Top" Width="91" IsDefault="True" Grid.Column="1" ToolTip="Get account status from user ID or find user ID from name"/>
                        <Button x:Name="Unlock" Content="Unlock" HorizontalAlignment="Left" Margin="26,74,0,0" VerticalAlignment="Top" Width="75" Grid.ColumnSpan="2" ToolTip="Unlock users account"/>
                        <Button x:Name="Password" Content="Reset Password" HorizontalAlignment="Left" Margin="20.675,74,0,0" VerticalAlignment="Top" Width="91" Grid.Column="1" ToolTip="Reset users password - this opens a new powershell window"/>
                        <Button x:Name="UserLog" Content="User Log" HorizontalAlignment="Left" Margin="122.675,74,0,0" VerticalAlignment="Top" Width="75" Grid.Column="1" ToolTip="See where user has logged in recently"/>
                        <Button x:Name="UserClear" Content="Clear" HorizontalAlignment="Left" Margin="26,265,0,0" VerticalAlignment="Top" Width="75" Grid.ColumnSpan="2" ToolTip="Clear form"/>
                        <TextBlock x:Name="NameText" HorizontalAlignment="Left" Margin="79.675,13,0,0" TextWrapping="Wrap" Text="Name" VerticalAlignment="Top" Grid.Column="1"/>
                        <TextBox x:Name="Name" HorizontalAlignment="Left" Height="23" Margin="43.675,34,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="180" Grid.Column="1"/>

                    </Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="7*"/>
                        <ColumnDefinition Width="32*"/>
                    </Grid.ColumnDefinitions>
                </Grid>
            </TabItem>
            <TabItem x:Name="PCInfo" Header="PC Info" Margin="8,0,-15,0">
                <Grid Background="#FFE5E5E5" Margin="0,3,0,-3">
                    <TextBox x:Name="PCInfo1" HorizontalAlignment="Left" Height="23" Margin="20,31,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="120"/>
                    <TextBlock x:Name="PCText" HorizontalAlignment="Left" Margin="27,10,0,0" TextWrapping="Wrap" Text="Enter PC Number" VerticalAlignment="Top"/>
                    <Button x:Name="CDrive" Content="C Drive" HorizontalAlignment="Left" Margin="117,67,0,0" VerticalAlignment="Top" Width="75" ToolTip="Opens the C drive of the remote PC"/>
                    <TextBox x:Name="IP" HorizontalAlignment="Left" Height="23" Margin="186,31,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="120"/>
                    <TextBlock x:Name="textBlock1" HorizontalAlignment="Left" Margin="216,10,0,0" TextWrapping="Wrap" Text="IP Address" VerticalAlignment="Top"/>
                    <TextBox x:Name="CurrentUser" HorizontalAlignment="Left" Height="23" Margin="345,31,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="120"/>
                    <TextBlock x:Name="textBlock2" HorizontalAlignment="Left" Margin="345,10,0,0" TextWrapping="Wrap" Text="Current Logged on User" VerticalAlignment="Top"/>
                    <Button x:Name="GetInfo" Content="Get Info" HorizontalAlignment="Left" Margin="20,67,0,0" VerticalAlignment="Top" Width="75" IsDefault="True" ToolTip="Gets the information of a PC either using the number or IP address, this includes; current logon status, last shutdown, current users mapped drives."/>
                    <TextBox x:Name="Ping" HorizontalAlignment="Left" Height="20" Margin="20,94,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="114" Background="#FFE5E5E5" Foreground="Red" IsInactiveSelectionHighlightEnabled="True" IsReadOnlyCaretVisible="True" SelectionBrush="#FFE5E5E5" IsTabStop="False" BorderThickness="0">
                        <TextBox.BorderBrush>
                            <SolidColorBrush Color="{DynamicResource Default}"/>
                        </TextBox.BorderBrush>
                    </TextBox>
                    <Button x:Name="Remote" Content="Remote On" HorizontalAlignment="Left" Margin="216,67,0,0" VerticalAlignment="Top" Width="75" ToolTip="Allows you to remote onto the PC"/>
                    <Button x:Name="mstsc" Content="RDP" HorizontalAlignment="Left" Margin="20,146,0,0" VerticalAlignment="Top" Width="75" ToolTip="Opens a remote desktop session with the remote PC"/>
                    <Button x:Name="PCClear" Content="Clear" HorizontalAlignment="Left" Margin="397,67,0,0" VerticalAlignment="Top" Width="75" ToolTip="Clears form"/>
                    <TextBox x:Name="PCData" HorizontalAlignment="Left" Height="175" Margin="108,100,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="377"/>
                    <Button x:Name="EventViewer" Content="Event Viewer" HorizontalAlignment="Left" Margin="307,67,0,0" VerticalAlignment="Top" Width="75" ToolTip="View event viewer of the remote PC"/>
                    <Button x:Name="PCLog" Content="PC Logs" HorizontalAlignment="Left" Margin="20,119,0,0" VerticalAlignment="Top" Width="75" ToolTip="View logs of who's logged into the remote PC"/>
                    <TextBox x:Name="Locked" HorizontalAlignment="Left" Height="19" Margin="465,26,-1,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="59" Background="#FFE5E5E5" Foreground="Red" FontSize="10" IsReadOnlyCaretVisible="True" IsInactiveSelectionHighlightEnabled="True" SelectionBrush="#FFE5E5E5" BorderBrush="#FFE5E5E5" BorderThickness="0"/>
                    <TextBox x:Name="Unlocked" HorizontalAlignment="Left" Height="19" Margin="464,45,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="59" Background="#FFE5E5E5" Foreground="#FF34CD3B" FontSize="10" IsReadOnlyCaretVisible="True" IsInactiveSelectionHighlightEnabled="True" BorderThickness="0">
                        <TextBox.BorderBrush>
                            <LinearGradientBrush EndPoint="0,20" MappingMode="Absolute" StartPoint="0,0">
                                <GradientStop Color="#FFABADB3"/>
                                <GradientStop Color="#FFE2E3EA"/>
                                <GradientStop Color="#FFE3E9EF"/>
                            </LinearGradientBrush>
                        </TextBox.BorderBrush>
                    </TextBox>
                    <Button x:Name="CMD" Content="CMD" HorizontalAlignment="Left" Margin="20,173,0,0" VerticalAlignment="Top" Width="75" ToolTip="Remotely access CMD of the remote PC"/>
                    <Button x:Name="Services" Content="Services" HorizontalAlignment="Left" Margin="20,200,0,0" VerticalAlignment="Top" Width="75" ToolTip="Opens services on the remote PC"/>
                    <Button x:Name="CompMgmt" Content="Comp Mgmt" HorizontalAlignment="Left" Margin="20,227,0,0" VerticalAlignment="Top" Width="75" ToolTip="Opens computer management of the remote PC"/>
                    <Button x:Name="Regedit" Content="Regedit" HorizontalAlignment="Left" Margin="20,254,0,0" VerticalAlignment="Top" Width="75" ToolTip="This just opens your local registry editor, but you can connect to a network location after it's open."/>
                </Grid>
            </TabItem>
            <TabItem x:Name="ExchangeTab" Header="Exchange" HorizontalAlignment="Right" Height="20" VerticalAlignment="Top" Width="65" Margin="0,0,-16,0">
                <Grid Background="#FFE5E5E5">
                    <TextBox x:Name="Email" HorizontalAlignment="Left" Height="23" Margin="21,29,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="198"/>
                    <TextBlock x:Name="textBlock3" HorizontalAlignment="Left" Margin="69,8,0,0" TextWrapping="Wrap" Text="Email Address" VerticalAlignment="Top"/>
                    <Button x:Name="License" Content="Add Licenses" HorizontalAlignment="Left" Margin="21,63,0,0" VerticalAlignment="Top" Width="91"/>
                    <Button x:Name="Mailboxes" Content="Mailbox Access" HorizontalAlignment="Left" Margin="21,90,0,0" VerticalAlignment="Top" Width="91"/>
                    <TextBox x:Name="EmailInfo" HorizontalAlignment="Left" Height="224" Margin="134,63,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="379"/>
                </Grid>
            </TabItem>
            <TabItem x:Name="OtherTab" Header="Other" HorizontalAlignment="Left" Height="20" VerticalAlignment="Top" Width="64" Margin="17,0,-17,0">
                <Grid Background="#FFE5E5E5">
                    <TextBox x:Name="OtherText" HorizontalAlignment="Left" Height="23" Margin="10,22,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="332"/>
                    <TextBlock x:Name="textBlock4" HorizontalAlignment="Left" Margin="119,1,0,0" TextWrapping="Wrap" Text="Folder Path" VerticalAlignment="Top"/>
                    <TextBox x:Name="OtherResults" HorizontalAlignment="Left" Height="208" Margin="115,79,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="398"/>
                    <Button x:Name="GetPerm" Content="Get Permissions" HorizontalAlignment="Left" Margin="10,50,0,0" VerticalAlignment="Top" Width="102" ToolTip="Get permissions of folder path"/>
                    <Button x:Name="ClearOther" Content="Clear" HorizontalAlignment="Left" Margin="438,10,0,0" VerticalAlignment="Top" Width="75" ToolTip="Clear form"/>
                </Grid>
            </TabItem>
        </TabControl>
        <DataGrid x:Name="dataGrid" Grid.Column="2" HorizontalAlignment="Left" Margin="2,-15,0,0" VerticalAlignment="Top"/>

    </Grid>
</Window>
"@ 

$inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'
 
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXML
#Read XAML
 
    $reader=(New-Object System.Xml.XmlNodeReader $xaml)
  try{$Form=[Windows.Markup.XamlReader]::Load( $reader )}
catch{Write-Host "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."}
 
#===========================================================================
# Load XAML Objects In PowerShell
#===========================================================================
 
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name)}
 
Function Get-FormVariables{
if ($global:ReadmeDisplay -ne $true){Write-host "If you need to reference this display again, run Get-FormVariables" -ForegroundColor Yellow;$global:ReadmeDisplay=$true}
write-host "Found the following interactable elements from our form" -ForegroundColor Cyan
get-variable WPF*
}
 
#Get-FormVariables

#===========================================================================
# Actually make the objects work
#===========================================================================
 
#Sample entry of how to add data to a field
 
#$vmpicklistView.items.Add([pscustomobject]@{'VMName'=($_).Name;Status=$_.Status;Other="Yes"})

                                                             

$WPFUserID.Text = $env:USERNAME
#####################################################
#               USER INFO
#####################################################

#-------------------------------------- 
 ## Get User Groups
#-------------------------------------- 
$WPFGetGroups.Add_Click({
    try {
    $user = Get-ADPrincipalGroupMembership $WPFUserID.Text
    $WPFUserData.Text =  ($user | select name | Out-String).trim()
    }

    catch {
    $WPFUserData.Text = "$($WPFUserID.Text) is invalid, please try again."
    }
}) 

#-------------------------------------- 
 ## Account Status
#-------------------------------------- 

$WPFAccStatus.Add_Click({

    if (($WPFUserID.text -ne "$null") -and ($WPFName.text -eq "$null")){
        $user = Get-ADUser $WPFUserID.Text –Properties SamAccountName, name,enabled,PasswordExpired,lockedout,Title,telephoneNumber,mail
        $WPFUserData.Text =  ($user | select enabled,PasswordExpired,lockedout,Title,telephoneNumber,mail | Out-String).trim()
        $WPFName.text = $user.name
        
        } 

    elseif(($WPFName.text -ne "$null") -and ($WPFUserID.text -eq "$null")) {
        $name = $WPFName.text
        $user = Get-ADUser -ldapfilter "(displayname=*$name*)" -Property samaccountname,displayname | Select-Object -Property samaccountname,displayname

        if($user -ne $null){
            $WPFUserData.text = ($user | Format-Table samaccountname, displayname -wrap | Out-String -Width 100).trim()
        }
        Else {
            $WPFUserData.text = "$name is invalid, please try again"
        }           
    }

    elseif(($WPFUserID.Text -eq "$null") -and ($WPFName.text -eq "$null")) {
        $WPFUserData.Text = "Please enter a name or username" 
        
    }
}) 

#-------------------------------------- 
 ## Unlock Account
#-------------------------------------- 
 $WPFUnlock.Add_Click({
    $user = Get-ADUser $WPFUserID.Text -Properties name,lockedout      
    if($user.lockedout -eq $true) {
        Unlock-ADAccount -Identity $WPFUserID.Text
        $WPFUserData.Text =  "$($user.name) is unlocked."
    }
    elseif($user -eq "$null") {
        $WPFUserData.Text = "$($user) is invalid, please try again."
    }
    else {        
        $WPFUserData.Text =  "$($user.name) is not locked."
    } 
    return
})

#-------------------------------------- 
 ## Reset Password
#--------------------------------------
    
$WPFPassword.add_click({
    $user = Get-ADUser $($WPFUserID.Text)

    try {
        powershell -Command "Start-Process 'powershell' -Verb RunAs -ArgumentList 'Set-ADAccountPassword -identity $($WPFUserID.text) -reset'"
        Set-ADUser $($WPFUserID.text) -ChangePasswordAtLogon $True
        
        If($?){
            $WPFUserData.Text = "$($WPFUserID.Text) password successfully changed"
        }

        else{
            $WPFUserData.Text = Write-Error
        }
    }

    catch {
        $WPFUserData.Text = "$($WPFUserID.Text) is invalid, please try again."
    }

})

#-------------------------------------- 
 ## User Log
#--------------------------------------

$WPFUserLog.Add_click({
    $WPFUserData.Text = Get-Content \\pasm73\UserLogs\Users\$($WPFUserID.Text).txt | Out-String
})

#-------------------------------------- 
 ## Clear User Form
#--------------------------------------

$WPFUserClear.Add_Click({
    $WPFUserData.text = ""
    $WPFUserID.Text = ""
    $WPFName.text = ""
})

#####################################################
#               PC INFO
#####################################################

$WPFPCInfo1.text = $env:COMPUTERNAME
#-------------------------------------- 
 ## Get PC Info
#--------------------------------------
$WPFGetInfo.Add_Click({
        #from PC Number
    if(($WPFPCInfo1.Text -ne "$null") -and ($WPFIP.Text -eq "$null") -and ($WPFCurrentUser.Text -eq "$null")){
        if(Test-Connection $($WPFPCInfo1.Text) -Count 2 -Quiet -ErrorAction Stop){
            $Bootup = (Get-CimInstance Win32_OperatingSystem -comp $WPFPCInfo1.Text | select LastBootUpTime | Out-String).trim(1)
            $Drives = (Get-WmiObject Win32_MappedLogicalDisk -ComputerName $WPFPCInfo1.Text | select name, providername | Format-table -Property name,providername -AutoSize | Out-String).Trim()
            $currentuser = Get-WmiObject -Class win32_computersystem -ComputerName $WPFPCInfo1.Text -Property username
            $unlocked = Get-Process LogonUI -ComputerName $($WPFPCInfo1.Text) -ErrorAction Ignore
            $result = [system.Net.Dns]::GetHostByName($WPFPCInfo1.text) 
            $WPFIP.text = $result.AddressList | ForEach-Object {$_.IPAddressToString } 
            $WPFCurrentUser.Text = $currentuser.username
            $WPFPCData.Text = Write-Output $Bootup $drives

                 #CHECK IF PC IS LOCKED
            if($currentuser.username -eq $null){
                $WPFCurrentUser.text = "No one"
                $WPFLocked.text = "Locked"
                }

            elseif($unlocked -and $WPFCurrentUser.Text) {
                $WPFLocked.text = "Locked"
                $WPFCurrentUser.Text = $currentuser.username
                }
            else {
                $WPFUnlocked.text = "Unlocked"
                $WPFPing.Text = ""
            }
        }
        
        else {
            $WPFPing.Text = "Offline"
        }
    }
       
        #from IP
    elseif(($WPFIP.Text -ne "$null") -and ($WPFPCInfo1.Text -eq "$null") -and ($WPFCurrentUser.text -eq "$null")){
        if(Test-Connection $($WPFIP.Text) -Count 2 -Quiet -ErrorAction Stop){
            $result = [System.Net.Dns]::GetHostByAddress($WPFIP.Text).hostname
            $WPFPCInfo1.text = $result.replace(".dli.wa.gov.au", $null)
            $currentuser = Get-WmiObject -Class win32_computersystem -ComputerName $WPFPCInfo1.Text
            $unlocked = Get-Process LogonUI -ComputerName $($WPFPCInfo1.Text) -ErrorAction Ignore
            $WPFCurrentUser.Text = $currentuser.username
            $WPFPing.Text = "" 
 
                #CHECK IF PC IS LOCKED
            if($currentuser.username -eq $null){
                $WPFCurrentUser.text = "No one"
                $WPFLocked.text = "Locked"
                $WPFPing.Text = ""
                }

            elseif($unlocked -and $currentuser) {
                $WPFLocked.text = "Locked"
                $WPFCurrentUser.Text = $currentuser.username
                $WPFPing.Text = ""
                }
            else {
                $WPFUnlocked.text = "Unlocked"
                $WPFPing.Text = ""
            }
        }
        
        else {
            $WPFPing.Text = "Offline"
        }
    }

    elseif(($WPFIP.Text -eq "$null") -and ($WPFPCInfo1.Text -eq "$null") -and ($WPFCurrentUser.text -eq "$null")){
        $WPFPCData.text = "Please enter a PC number or IP address"
    }

    else {
        $WPFPing.Text = "Offline"
    }
})

#-------------------------------------- 
 ## Clear PC Form
#--------------------------------------

$WPFPCClear.add_click({
    $WPFPCInfo1.Text = ""
    $WPFIP.Text = ""
    $WPFCurrentUser.Text = ""
    $WPFPing.Text = ""
    $WPFPCData.Text = ""
    $WPFUnlocked.Text = ""
    $WPFLocked.Text = ""
})

#-------------------------------------- 
 ## C Drive
#--------------------------------------

$WPFCDrive.add_click({
    explorer.exe \\$($WPFPCInfo1.text)\c$

})

#-------------------------------------- 
 ## Remote On
#--------------------------------------

$WPFRemote.add_click({
    & 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\i386\CmRcViewer.exe'$($WPFPCInfo1.text)
})

#-------------------------------------- 
 ## Remote Desktop - MSTSC
#--------------------------------------

$WPFmstsc.add_click({
    & 'C:\Windows\System32\mstsc.exe' /v:$($Wpfpcinfo1.Text)
})

#-------------------------------------- 
 ## Event Viewer
#--------------------------------------

$WPFEventViewer.add_click({
    & eventvwr $($WPFPCInfo1.Text)
})

#-------------------------------------- 
 ## PC Logs
#--------------------------------------

$WPFPCLog.add_click({
    $WPFPCData.Text = Get-Content \\pasm73\UserLogs\Computers\$($WPFPCInfo1.Text).txt | Out-String
})

#-------------------------------------- 
 ## CMD
#--------------------------------------

$WPFCMD.add_click({
    $PC = $WPFPCInfo1.Text
    powershell -Command "Start-Process 'cmd' -Verb RunAs -ArgumentList '/c psexec -s \\$PC cmd'"
    
})

#-------------------------------------- 
 ## Services
#--------------------------------------

$WPFServices.add_click({
    Try{
        & services.msc /computer=$($WPFPCInfo1.Text)
    }

    Catch {
        $WPFPCInfo1.Text = "Unable to access services of $($WPFPCInfo1.Text)"
    }
})

#-------------------------------------- 
 ## Computer Management
#--------------------------------------

$WPFCompMgmt.add_click({
    & compmgmt.msc /computer=$($WPFPCInfo1.Text)
})

#-------------------------------------- 
 ## Regedit
#--------------------------------------

$WPFRegedit.add_click({
    & regedit.exe
})

#####################################################
#               EXCHANGE
#####################################################




#-------------------------------------- 
 ## Add Licenses
#--------------------------------------


#-------------------------------------- 
 ## Get Mailbox Permission
#--------------------------------------

$WPFMailboxes.add_click({
    #$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $cred -Authentication Basic -AllowRedirection
    #Import-PSSession $session
    $UserCredential = Get-Credential

    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
    Import-PSSession $session -AllowClobber
    #$WPFEmailInfo.text = Get-MailboxFolderPermission rachel.moore@landgate.wa.gov.au | Write-Output
    $WPFEmailInfo.text = Get-Mailbox -identity rachel.moore@landgate.wa.gov.au | Get-MailboxFolderPermission | Select identity, user | ft identity, user | Out-String
}) 

#####################################################
#               OTHER
#####################################################

#-------------------------------------- 
 ## Folder Permissions
#--------------------------------------

$WPFGetPerm.add_click({
    $WPFOtherResults.text = get-acl $($WPFOtherText.text) | %{ $_.Access  } | ft -property IdentityReference, FileSystemRights | Out-String
})

$WPFClearOther.add_click({
    $WPFOtherResults.text = ""
    $WPFOtherText.text = ""
})

#===========================================================================
# Shows the form
#===========================================================================
#write-host "To show the form, run the following" -ForegroundColor Cyan
#'$Form.ShowDialog() | out-null'
$Form.ShowDialog() | Out-Null