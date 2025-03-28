﻿using System;
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
                        EndOffset = 0x7ffff,
                        Hash = new byte[] { 0x0b, 0x6d, 0xc0, 0x1a, 0xd2, 0x80, 0x1c, 0x93, 0x84, 0x91, 0xd3, 0x16, 0x06, 0x7b, 0x5c, 0xf5, 0xb4, 0x7c, 0x58, 0x64, 0xe1, 0xce, 0x81, 0x8b, 0x99, 0x57, 0x09, 0x8f, 0x2a, 0xf8, 0xbf, 0x8c }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x80000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0xf3, 0x87, 0xe0, 0x28, 0xcb, 0xed, 0x03, 0xd5, 0xd7, 0xcd, 0x1a, 0x77, 0x2e, 0x20, 0x95, 0xcb, 0xf9, 0xce, 0x89, 0x2e, 0x67, 0x4e, 0x89, 0xf2, 0x60, 0x9b, 0xd4, 0x42, 0xe4, 0x30, 0x87, 0x84 }
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
                        EndOffset = 0x7ffff,
                        Hash = new byte[] { 0x3d, 0x5a, 0xf6, 0xdd, 0x93, 0xec, 0x0d, 0x13, 0xea, 0xc6, 0x8d, 0x11, 0x14, 0x5c, 0x7e, 0xec, 0x02, 0x66, 0x64, 0xe1, 0x1f, 0x9d, 0xf4, 0xb8, 0x1f, 0x2c, 0xac, 0x50, 0xe9, 0xce, 0xf3, 0xde }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x80000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x35, 0x3d, 0x0f, 0xda, 0x2c, 0xbe, 0xd9, 0x92, 0x5d, 0xca, 0xd0, 0xc5, 0x07, 0x00, 0x2b, 0xa6, 0xab, 0x66, 0xa1, 0x22, 0x61, 0x9b, 0xbd, 0xf2, 0x76, 0xf8, 0x85, 0x55, 0xd7, 0xe6, 0x31, 0x0f }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x51, 0x51, 0x8f, 0x6e, 0xbf, 0xc2, 0x6d, 0xfe, 0x1a, 0x22, 0xda, 0xeb, 0x57, 0xc6, 0x5d, 0x42, 0xe1, 0x64, 0xfa, 0x36, 0x87, 0x37, 0x6e, 0xa7, 0xa0, 0x36, 0xfe, 0xa0, 0x56, 0x43, 0xa7, 0x3e }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Color Ver.3",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0xabc0, SeekOrigin.Begin);
                    return br.ReadUInt32() == 0x9217f060;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x7ffff,
                        Hash = new byte[] { 0x33, 0xb1, 0x11, 0x01, 0x98, 0x67, 0x6a, 0x18, 0x0d, 0x01, 0x7f, 0x20, 0x16, 0xf8, 0xd2, 0xe4, 0xb5, 0x26, 0xa1, 0x71, 0xde, 0xc4, 0xd4, 0x4f, 0xfd, 0x9c, 0x9b, 0xe7, 0x77, 0xc4, 0xe5, 0x4a }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x80000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x56, 0x5b, 0x63, 0xd7, 0x47, 0x59, 0xce, 0x16, 0x63, 0x57, 0x69, 0x28, 0xbf, 0xa5, 0x54, 0x03, 0xd7, 0xcd, 0xef, 0xe4, 0xb8, 0xeb, 0xa4, 0x10, 0x9d, 0xd6, 0x39, 0xae, 0x96, 0xaa, 0xb8, 0xc5 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x23, 0xa3, 0xee, 0x57, 0xf4, 0x40, 0x1f, 0xe8, 0x9c, 0xaa, 0x43, 0x93, 0x2f, 0x26, 0xf5, 0xad, 0x6c, 0xce, 0xf4, 0x4c, 0xd7, 0xfb, 0x55, 0x9e, 0x41, 0xb6, 0x6f, 0x64, 0x17, 0xb0, 0x0b, 0x66 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Color Ver.4",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x9740, SeekOrigin.Begin);
                    return br.ReadUInt32() == 0x9116f060;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x7ffff,
                        Hash = new byte[] { 0xc2, 0x4c, 0x74, 0xa5, 0x7f, 0x6d, 0x35, 0xaf, 0xed, 0x04, 0x47, 0xd9, 0xf4, 0x50, 0xfd, 0xb3, 0x13, 0xbe, 0x25, 0x38, 0xee, 0x26, 0x03, 0x76, 0x8a, 0x2c, 0x3e, 0x6d, 0xb6, 0xa3, 0x9e, 0x10 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x80000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0xcd, 0xc5, 0x30, 0x53, 0xe8, 0x36, 0xd6, 0x42, 0x11, 0x96, 0x7f, 0xe7, 0x4a, 0x41, 0x99, 0xeb, 0x77, 0xf5, 0x49, 0xab, 0xfb, 0x34, 0xc2, 0x2a, 0xef, 0x4a, 0x24, 0x16, 0x76, 0x06, 0x27, 0x20 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x2c, 0xc2, 0x9a, 0xea, 0x57, 0xe8, 0x94, 0xa7, 0xfa, 0x97, 0x56, 0x7d, 0x24, 0xf1, 0x06, 0xed, 0x53, 0x47, 0xb0, 0x60, 0x6f, 0xde, 0x66, 0xbd, 0x0c, 0xc2, 0xcc, 0xba, 0x60, 0xdc, 0x79, 0x48 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Color Ver.5",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0xa0d0, SeekOrigin.Begin);
                    return br.ReadUInt32() == 0x912bf060;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x7ffff,
                        Hash = new byte[] { 0x51, 0xa1, 0x95, 0x8c, 0xbb, 0x22, 0x66, 0xf9, 0x04, 0xfb, 0x75, 0xb6, 0x57, 0x84, 0xec, 0x1e, 0xa4, 0xb0, 0x37, 0xa7, 0x6d, 0xa9, 0xd9, 0x98, 0x6f, 0x5c, 0xc6, 0xbe, 0x47, 0x17, 0x53, 0x73 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x80000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0xf0, 0xef, 0xa6, 0xe4, 0xe4, 0xa7, 0xe2, 0x98, 0x62, 0x0f, 0x10, 0xb7, 0xe9, 0x88, 0x6c, 0x79, 0x97, 0x56, 0x67, 0xc5, 0x5c, 0x9a, 0xce, 0xbd, 0xec, 0x1f, 0xfc, 0x94, 0xb0, 0x69, 0xe6, 0x08 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x2b, 0x6b, 0x45, 0x10, 0x92, 0x9b, 0x70, 0xc5, 0x9f, 0x00, 0xc2, 0xbc, 0x28, 0x37, 0xda, 0x3f, 0x12, 0xfb, 0x51, 0x2c, 0x44, 0x71, 0x9a, 0x10, 0x40, 0x9d, 0xf0, 0xf7, 0x9b, 0x83, 0xad, 0xbd }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Pendulum Color 1 Nature Spirits",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x1733e, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9640 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0d08 && br.ReadUInt16() == 0xd6e4;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = new byte[] { 0xcd, 0x4a, 0x52, 0x88, 0x54, 0x47, 0xe8, 0xd4, 0x8e, 0x38, 0xa4, 0x47, 0xb2, 0x6a, 0x3d, 0x08, 0x88, 0xfa, 0x08, 0x81, 0x48, 0x62, 0x5a, 0xbe, 0x5c, 0xd0, 0x9d, 0xae, 0x55, 0xb6, 0x93, 0xd1 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x4f, 0x3e, 0x03, 0x75, 0x5c, 0xbf, 0x00, 0x63, 0x00, 0x69, 0x96, 0x56, 0x58, 0x36, 0x52, 0x4e, 0xfb, 0x46, 0xb9, 0x37, 0x50, 0xd0, 0xff, 0xda, 0x1b, 0xb0, 0xdd, 0x19, 0x9d, 0x87, 0xbe, 0x70 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0xe2, 0x4b, 0x41, 0xcc, 0xe4, 0xf7, 0x0c, 0xe6, 0x6d, 0x0f, 0xd3, 0xab, 0xe3, 0xff, 0xf5, 0x50, 0x72, 0xad, 0x6a, 0x9c, 0x7d, 0x23, 0x65, 0x52, 0x04, 0xf3, 0xbc, 0xa3, 0xd7, 0xe8, 0xe4, 0x93 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Pendulum Color 2 Deep Savers",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x172fc, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9641 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0d08 && br.ReadUInt16() == 0xd6e4;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = new byte[] { 0xcb, 0xd1, 0x72, 0xdf, 0x90, 0x2e, 0x73, 0x07, 0x83, 0xf9, 0x88, 0x9d, 0x33, 0x77, 0xcb, 0x6c, 0x6f, 0x5f, 0x30, 0x0f, 0x89, 0x97, 0x1e, 0x21, 0x68, 0x30, 0x2f, 0x3f, 0x8d, 0x14, 0x76, 0xa2 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x37, 0xd2, 0x31, 0xc9, 0xb8, 0x51, 0x8d, 0x6d, 0xa5, 0x5c, 0x51, 0xb5, 0x42, 0x78, 0x6f, 0xf1, 0xdb, 0xe8, 0x6a, 0x0b, 0x05, 0x94, 0x39, 0x8e, 0x7b, 0xb3, 0x0b, 0x43, 0x59, 0x53, 0xa6, 0x2c }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x4a, 0x79, 0x80, 0x86, 0x37, 0x53, 0x46, 0x0d, 0xeb, 0xe7, 0x46, 0x98, 0xb9, 0x82, 0xbf, 0xf5, 0xd9, 0x27, 0x92, 0xba, 0x12, 0xa8, 0x8a, 0x43, 0xb4, 0xce, 0xb8, 0xf4, 0x3d, 0xe2, 0x8a, 0x49 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Pendulum Color 3 Nightmare Soldiers",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x17302, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9642 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0d08 && br.ReadUInt16() == 0xd6e4;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = new byte[] { 0x85, 0x60, 0xf4, 0x4a, 0x77, 0x8e, 0xb0, 0x72, 0x1a, 0x70, 0x15, 0x19, 0xf0, 0xa8, 0x9e, 0xa2, 0x6b, 0x28, 0x77, 0x87, 0x75, 0xd8, 0x6d, 0xab, 0x20, 0x2c, 0x80, 0x15, 0x03, 0x31, 0x5d, 0x50 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0xef, 0x1a, 0x03, 0x11, 0xc7, 0xf3, 0x31, 0x2b, 0x45, 0x53, 0xec, 0xaf, 0x20, 0xa1, 0xc8, 0xc0, 0x93, 0x4a, 0x2f, 0x2e, 0x87, 0x06, 0x07, 0x5d, 0xe4, 0x12, 0x88, 0x06, 0x27, 0x0d, 0x55, 0xe3 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x9e, 0xa6, 0xd4, 0x8b, 0x4b, 0x22, 0xb1, 0x0b, 0xd8, 0xbd, 0x2b, 0x3c, 0xa4, 0x3a, 0xd9, 0x60, 0x91, 0x76, 0x63, 0x83, 0x7b, 0x3e, 0x33, 0x19, 0xea, 0x1e, 0x46, 0x7f, 0x79, 0x2f, 0x49, 0xfb }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Pendulum Color 4 Wind Guardians",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x1791c, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9643 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0d08 && br.ReadUInt16() == 0xd6e4;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = new byte[] { 0x3a, 0x9c, 0x22, 0xbc, 0x2e, 0x5a, 0x7c, 0xcf, 0xf7, 0xd3, 0x81, 0xb8, 0xbe, 0xb6, 0x9a, 0xf7, 0x0e, 0x0c, 0x14, 0xcb, 0xa4, 0x03, 0xf4, 0x80, 0x3e, 0x24, 0x8d, 0x1d, 0xbd, 0x4c, 0x35, 0x31 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x80, 0x4a, 0x73, 0x44, 0x6b, 0xd9, 0x09, 0x56, 0x22, 0xf8, 0x53, 0xb5, 0x1d, 0xd5, 0x6f, 0x75, 0x56, 0x9a, 0x24, 0xfd, 0x90, 0x1a, 0xb3, 0xae, 0xaf, 0x9f, 0x32, 0x6d, 0xc4, 0x00, 0x78, 0x3f }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0xc1, 0xa5, 0x18, 0xec, 0x64, 0xef, 0x53, 0x3a, 0x61, 0xdd, 0xeb, 0xfa, 0x0a, 0xde, 0x27, 0x0c, 0xea, 0x88, 0xd3, 0xb1, 0x84, 0x11, 0xf1, 0x6f, 0xe2, 0xc9, 0x9a, 0x05, 0x87, 0x88, 0x86, 0xd4 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Pendulum Color 5 Metal Empire",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x17928, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9644 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0d08 && br.ReadUInt16() == 0xd6e4;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = new byte[] { 0xd6, 0x03, 0x77, 0x40, 0x45, 0x27, 0x9e, 0x92, 0xb5, 0xd7, 0x94, 0x5a, 0x92, 0x86, 0xe3, 0x8a, 0x10, 0x7d, 0x89, 0xee, 0x30, 0x1a, 0xd6, 0xe2, 0x9b, 0x0f, 0x47, 0xf2, 0xb2, 0xf0, 0xc1, 0x82 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0xad, 0x4c, 0x62, 0x80, 0x71, 0xe7, 0xc0, 0x38, 0x38, 0x33, 0x4d, 0x1f, 0x3d, 0x38, 0x24, 0xc7, 0x58, 0xc8, 0xd6, 0x7e, 0x1c, 0xf1, 0x16, 0xb1, 0x25, 0x94, 0x43, 0xf3, 0xf1, 0x62, 0xa9, 0x80 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0xfe, 0x09, 0x7b, 0xa6, 0xa3, 0x24, 0xca, 0x7f, 0x49, 0x96, 0x27, 0xf9, 0xda, 0x0d, 0x74, 0xc0, 0x1b, 0x74, 0x97, 0x59, 0xe4, 0x62, 0x4e, 0xb1, 0x35, 0x3f, 0x5b, 0x49, 0xce, 0xf7, 0x95, 0x40 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Pendulum Color Zero Virus Busters",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0x18da8, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9645 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0d08 && br.ReadUInt16() == 0xd6e4;
                },
                Regions = new[]
                {
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = new byte[] { 0x88, 0xbb, 0x86, 0x35, 0xf5, 0xff, 0x0b, 0xad, 0xbd, 0x1b, 0x4a, 0x8f, 0x61, 0x82, 0x9d, 0xc9, 0xc4, 0x36, 0x93, 0xb3, 0x9d, 0x16, 0x7d, 0x21, 0xe5, 0x7e, 0xcf, 0xa5, 0x9c, 0x1a, 0x3a, 0x09 }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = new byte[] { 0x60, 0x5f, 0xc6, 0xc1, 0xf1, 0xca, 0xe8, 0xb7, 0xa3, 0x33, 0x0e, 0xa6, 0x2a, 0xce, 0xd3, 0xc0, 0x5f, 0xc3, 0xb0, 0xe5, 0x1c, 0x46, 0x25, 0x3e, 0xf8, 0xcc, 0x42, 0x72, 0x0e, 0x7f, 0x04, 0x6d }
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = new byte[] { 0x34, 0x4e, 0x10, 0x3b, 0x9a, 0x25, 0x4f, 0xc0, 0x58, 0x27, 0x1f, 0xb5, 0x2d, 0x5f, 0x71, 0x8b, 0x62, 0x32, 0xb2, 0x90, 0xac, 0x60, 0x84, 0xce, 0x14, 0xbb, 0x56, 0x79, 0x67, 0xec, 0x0f, 0xf4 }
                    }
                }
            },
            new FirmwareInfo
            {
                Name = "Digimon Color Monster Hunter 20th Edition",
                IdentifierFunction = (br) =>
                {
                    br.BaseStream.Seek(0xb474, SeekOrigin.Begin);
                    return br.ReadUInt16() == 0x9645 && br.ReadUInt16() == 0xfe00 && br.ReadUInt16() == 0x990c && br.ReadUInt16() == 0x0cfe && br.ReadUInt16() == 0xd6e4;
                },
                Regions =
                [
                    new CheckRegion
                    {
                        StartOffset = 0,
                        EndOffset = 0x3fffff,
                        Hash = [0x12, 0x60, 0x47, 0xb6, 0x3f, 0xda, 0x7c, 0x2e, 0xff, 0x8b, 0x8c, 0xc4, 0x53, 0xd8, 0x84, 0x9c, 0x74, 0xeb, 0xe3, 0xf0, 0xaf, 0x66, 0xb9, 0xe6, 0x7e, 0x03, 0xf2, 0xfe, 0xca, 0x33, 0xb9, 0x85]
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x400000,
                        EndOffset = 0x7fcfff,
                        Hash = [0xdd, 0xa0, 0x51, 0x42, 0xbb, 0x4f, 0x77, 0x76, 0xa0, 0x87, 0xe3, 0x1b, 0x1d, 0x1c, 0x4a, 0x2e, 0x33, 0x89, 0xfa, 0x84, 0xf7, 0x1e, 0x5d, 0x72, 0xd0, 0xb5, 0x89, 0x72, 0x74, 0x36, 0x0f, 0x30]
                    },
                    new CheckRegion
                    {
                        StartOffset = 0x7ff000,
                        EndOffset = 0x7fffff,
                        Hash = [0x2d, 0x15, 0xdd, 0xba, 0xb0, 0xd8, 0x57, 0x24, 0x6c, 0xb6, 0x5c, 0xf5, 0xaa, 0xf1, 0x9f, 0xd5, 0xa3, 0x17, 0xf6, 0x01, 0xb2, 0x32, 0x59, 0x14, 0x91, 0xa4, 0x25, 0xb9, 0xca, 0x7d, 0x01, 0xdd]
                    }
                ]
            },
        }.ToImmutableList();

        public static void CheckFirmware(Stream stream)
        {
            BinaryReader br = new BinaryReader(stream);
            FirmwareInfo? info = null;
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
