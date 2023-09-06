using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DmcHashCheck
{
    internal static class HashChecker
    {
        public class CheckRegion
        {
            public int StartOffset { get; set; }
            public int EndOffset { get; set; }
            public byte[] Hash { get; set; }
        }

        public class FirmwareInfo
        {
            public string Name { get; set; }
            public Func<BinaryReader, bool> IdentifierFunction { get; set; }
            public CheckRegion[] Regions { get; set; }
        }

        public static readonly IReadOnlyList<FirmwareInfo> FIRMWARES = new List<FirmwareInfo>()
        {
            new FirmwareInfo
            {
                Name = "Digimon Color",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x9f6a, SeekOrigin.Begin);
                    return br.ReadUInt32() == 0x0344f060;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0xac, 0x6b, 0x8f, 0x14, 0x18, 0x69, 0xdf, 0x57, 0x89, 0x0a, 0x33, 0xb1, 0xff, 0x01, 0x2c, 0xed, 0x7d, 0x88, 0xa4, 0x66, 0x99, 0xef, 0x52, 0xc3, 0x7c, 0xfc, 0x2d, 0x7a, 0xbf, 0x58, 0xaa, 0xc4 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0xf4, 0x9b, 0x86, 0x05, 0x61, 0xe2, 0xee, 0x40, 0x86, 0x1f, 0x83, 0x82, 0x4b, 0x29, 0x23, 0x24, 0x60, 0x8e, 0x8f, 0xb0, 0x59, 0x73, 0x6d, 0x03, 0x91, 0xdc, 0xdd, 0xab, 0xac, 0x1c, 0xa9, 0x65 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Color Ver.2",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x7366, SeekOrigin.Begin);
                    return br.ReadUInt32() == 0x8e11f060;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x7e, 0xb7, 0x4d, 0x79, 0x3d, 0xdb, 0xb5, 0x61, 0x88, 0x07, 0x46, 0x30, 0xe9, 0xf3, 0xe6, 0x56, 0x7d, 0x66, 0x18, 0xb2, 0x97, 0xc2, 0x5f, 0x61, 0x4d, 0x05, 0xdd, 0xab, 0xc8, 0xd9, 0x05, 0x2d }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x51, 0x51, 0x8f, 0x6e, 0xbf, 0xc2, 0x6d, 0xfe, 0x1a, 0x22, 0xda, 0xeb, 0x57, 0xc6, 0x5d, 0x42, 0xe1, 0x64, 0xfa, 0x36, 0x87, 0x37, 0x6e, 0xa7, 0xa0, 0x36, 0xfe, 0xa0, 0x56, 0x43, 0xa7, 0x3e }
                    }
                }
            }
        }.ToImmutableList();

        public static void CheckFirmware(Stream stream)
        {
            BinaryReader br = new BinaryReader(stream);
            FirmwareInfo info = null;
            foreach (var i in FIRMWARES)
            {
                if (i.IdentifierFunction(br))
                {
                    info = i;
                    break;
                }
            }

            if (info == null)
            {
                Console.WriteLine("Firmware not identified.");
                return;
            }

            Console.WriteLine($"Firmware identified: {info.Name}");

            using SHA256 sha = SHA256.Create();

            bool isValid = true;
            foreach (var region in info.Regions)
            {
                stream.Seek(region.StartOffset, SeekOrigin.Begin);
                byte[] bytes = br.ReadBytes(region.EndOffset - region.StartOffset + 1);
                byte[] hash = sha.ComputeHash(bytes);
                if (!((ReadOnlySpan<byte>)hash).SequenceEqual((ReadOnlySpan<byte>)region.Hash))
                {
                    isValid = false;
                    Console.WriteLine($"Region from 0x{region.StartOffset:x} to 0x{region.EndOffset:x} failed to verify.");
                }
            }

            Console.WriteLine(isValid ? "Firmware data verified." : "One or more regions of firmware data failed to verify.");
        }
    }
}
