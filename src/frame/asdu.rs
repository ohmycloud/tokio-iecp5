use std::{
    fmt::{Debug, Display},
    io::Cursor,
};

use anyhow::{anyhow, Result};
use bit_struct::*;
use byteorder::ReadBytesExt;
use bytes::{BufMut, Bytes, BytesMut};

// ASDUSizeMax asdu max size
pub(crate) const ASDU_SIZE_MAX: usize = 249;

// ASDU format
//       | data unit identification | information object <1..n> |
//
//       | <------------  data unit identification ------------>|
//       | typeID | variable struct | cause  |  common address  |
// bytes |    1   |      1          | [1,2]  |      [1,2]       |
//       | <------------  information object ------------------>|
//       | object address | element set  |  object time scale   |
// bytes |     [1,2,3]    |              |                      |

// InvalidCommonAddr is the invalid common address.
pub const INVALID_COMMON_ADDR: u16 = 0;

// GlobalCommonAddr is the broadcast address. Use is restricted
// to C_IC_NA_1, C_CI_NA_1, C_CS_NA_1 and C_RP_NA_1.
// When in 8-bit mode 255 is mapped to this value on the fly.
#[allow(dead_code)]
const GLOBAL_COMMON_ADDR: u16 = 255;

pub const IDENTIFIER_SIZE: usize = 6;

pub type OriginAddr = u8;
pub type CommonAddr = u16;

#[derive(Debug, Clone)]
pub struct Asdu {
    pub identifier: Identifier,
    pub raw: Bytes,
}

impl Display for Asdu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.identifier.to_string().as_str())?;
        f.write_str(
            self.raw
                .to_vec()
                .iter()
                .map(|b| format!("[{:02X}]", b))
                .collect::<Vec<String>>()
                .join("")
                .as_str(),
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Identifier {
    /// 类型标识
    pub type_id: TypeID,
    /// 可变结构
    pub variable_struct: VariableStruct,
    /// 传送原因
    pub cot: CauseOfTransmission,
    // 源站址(一般不使用, 置0)
    pub orig_addr: OriginAddr,
    // (1~254为站地址, 255为全局地址, 0不使用)
    pub common_addr: CommonAddr,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[{:02X}]", self.type_id as u8))?;
        f.write_fmt(format_args!("[{:02X}]", self.variable_struct.raw()))?;
        f.write_fmt(format_args!("[{:02X}]", self.cot.raw()))?;
        f.write_fmt(format_args!("[{:02X}]", self.orig_addr))?;
        let common_addr = self.common_addr.to_le_bytes();
        f.write_fmt(format_args!("[{:02X}]", common_addr[0]))?;
        f.write_fmt(format_args!("[{:02X}]", common_addr[1]))?;
        Ok(())
    }
}

bit_struct! {
    pub struct VariableStruct(u8) {
        /// 是否顺序
        is_sequence: u1,
        /// 信息元素个数
        number: u7,
    }
}

enums! {
    pub Cause {
        Unused,                     // 未用
        Periodic,                   // 周期、循环 （遥测）
        Background,                 // 背景扫描（遥信）（遥测）
        Spontaneous,                // 突发(自发) （遥信）（遥测）
        Initialized,                // 初始化完成
        Request,                    // 请求或被请求 （遥信被请求）（遥测被请求）
        Activation,                 // 激活（激活）（遥控、参数设置 控制方向）
        ActivationCon,              // 激活确认（激活确认）（遥控、参数设置 监视方向）
        Deactivation,               // 停止激活 （遥控、参数设置 控制方向）
        DeactivationCon,            // 停止激活确认（遥控、参数设置 监视方向）
        ActivationTerm,             // 激活终止 （遥控 监视方向）
        FileTransfer,               // 文件传输
        ReturnInfoRemote,           // 远程信息返回
        ReturnInfoLocal,            // 本地信息返回
        Authentication,             // 认证
        SessionKey,                 // 会话密钥
        UserRoleAndUpdateKey,       // 用户角色和更新密钥
        Reserved1,                  // 保留1
        Reserved2,                  // 保留2
        Reserved3,                  // 保留3
        InterrogatedByStation,      // 被站点询问
        InterrogatedByGroup1,       // 被组1询问
        InterrogatedByGroup2,       // 被组2询问
        InterrogatedByGroup3,       // 被组3询问
        InterrogatedByGroup4,       // 被组4询问
        InterrogatedByGroup5,       // 被组5询问
        InterrogatedByGroup6,       // 被组6询问
        InterrogatedByGroup7,       // 被组7询问
        InterrogatedByGroup8,       // 被组8询问
        InterrogatedByGroup9,       // 被组9询问
        InterrogatedByGroup10,      // 被组10询问
        InterrogatedByGroup11,      // 被组11询问
        InterrogatedByGroup12,      // 被组12询问
        InterrogatedByGroup13,      // 被组13询问
        InterrogatedByGroup14,      // 被组14询问
        InterrogatedByGroup15,      // 被组15询问
        InterrogatedByGroup16,      // 被组16询问
        RequestByGeneralCounter,    // 通过通用计数器请求
        RequestByGroup1Counter,     // 通过组1计数器请求
        RequestByGroup2Counter,     // 通过组2计数器请求
        RequestByGroup3Counter,     // 通过组3计数器请求
        RequestByGroup4Counter,     // 通过组4计数器请求
        Reserved4,                  // 保留4
        Reserved5,                  // 保留5
        UnknownTypeID,              // 未知的类型标识（遥控、参数设置 监视方向）
        UnknownCOT,                 // 未知的传送原因（遥控、参数设置 监视方向）
        UnknownCA,                  // 未知的应用服务数据单元公共地址（遥控、参数设置 监视方向）
        UnknownIOA,                 // 未知的信息对象地址（遥控、参数设置 监视方向）
    }
}

bit_struct! {
    pub struct CauseOfTransmission(u8) {
        /// T(test) true: 实验, false: 未实验
        test: bool,
        /// P/N true: 否定确认, false: 肯定确认
        positive: bool,
        /// 传送原因
        cause: Cause,
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TypeID {
    M_SP_NA_1 = 1,  // 单点信息
    M_SP_TA_1 = 2,  // 带时标单点信息
    M_DP_NA_1 = 3,  // 双点信息
    M_DP_TA_1 = 4,  // 带时标双点信息
    M_ST_NA_1 = 5,  // 步位置信息
    M_ST_TA_1 = 6,  // 带时标步位置信息
    M_BO_NA_1 = 7,  // 32 比特串
    M_BO_TA_1 = 8,  // 带时标 32 比特串
    M_ME_NA_1 = 9,  // 测量值, 归一化值
    M_ME_TA_1 = 10, // 测量值, 带时标归一化值
    M_ME_NB_1 = 11, // 测量值, 标度化值
    M_ME_TB_1 = 12, // 测量值, 带时标标度化值
    M_ME_NC_1 = 13, // 测量值, 短浮点数
    M_ME_TC_1 = 14, // 测量值, 带时标短浮点数
    M_IT_NA_1 = 15, // 累计量
    M_IT_TA_1 = 16, // 带时标累计量
    M_EP_TA_1 = 17, // 带时标继电保护装置事件
    M_EP_TB_1 = 18, // 带时标继电保护装置成组启动事件
    M_EP_TC_1 = 19, // 带时标继电保护装置成组输出电路信息
    M_PS_NA_1 = 20, // 带状态检出的成组单点信息
    M_ME_ND_1 = 21, // 不带品质描述的归一化测量值
    M_SP_TB_1 = 30, // 带时标 CP56Time2a 的单点信息
    M_DP_TB_1 = 31, // 带时标 CP56Time2a 的双点信息
    M_ST_TB_1 = 32, // 带时标 CP56Time2a 的步位置信息
    M_BO_TB_1 = 33, // 带时标 CP56Time2a 的 32 比特串
    M_ME_TD_1 = 34, // 带时标 CP56Time2a 的测量值, 归一化值
    M_ME_TE_1 = 35, // 带时标 CP56Time2a 的测量值, 标度化值
    M_ME_TF_1 = 36, // 带时标 CP56Time2a 的测量值, 短浮点数
    M_IT_TB_1 = 37, // 带时标 CP56Time2a 的累计量
    M_EP_TD_1 = 38, // 带时标 CP56Time2a 的继电保护装置事件
    M_EP_TE_1 = 39, // 带时标 CP56Time2a 的继电保护装置成组启动事件
    M_EP_TF_1 = 40, // 带时标 CP56Time2a 的继电保护装置成组输出电路信息
    S_IT_TC_1 = 41,
    C_SC_NA_1 = 45, // 单命令
    C_DC_NA_1 = 46, // 双命令
    C_RC_NA_1 = 47, // 步调节命令
    C_SE_NA_1 = 48, // 设点命令, 归一化值
    C_SE_NB_1 = 49, // 设点命令, 标度化值
    C_SE_NC_1 = 50, // 设点命令, 短浮点数
    C_BO_NA_1 = 51, // 32 比特串
    C_SC_TA_1 = 58, // 带时标 CP56Time2a 的单命令
    C_DC_TA_1 = 59, // 带时标 CP56Time2a 的双命令
    C_RC_TA_1 = 60, // 带时标 CP56Time2a 的步调节命令
    C_SE_TA_1 = 61, // 带时标 CP56Time2a 的设点命令, 归一化值
    C_SE_TB_1 = 62, // 带时标 CP56Time2a 的设点命令, 标度化值
    C_SE_TC_1 = 63, // 带时标 CP56Time2a 的设点命令, 短浮点数
    C_BO_TA_1 = 64, // 带时标 CP56Time2a 的 32 比特串
    M_EI_NA_1 = 70, // 初始化结束
    S_CH_NA_1 = 81,
    S_RP_NA_1 = 82,
    S_AR_NA_1 = 83,
    S_KR_NA_1 = 84,
    S_KS_NA_1 = 85,
    S_KC_NA_1 = 86,
    S_ER_NA_1 = 87,
    S_US_NA_1 = 90,
    S_UQ_NA_1 = 91,
    S_UR_NA_1 = 92,
    S_UK_NA_1 = 93,
    S_UA_NA_1 = 94,
    S_UC_NA_1 = 95,
    C_IC_NA_1 = 100, // 总召唤命令
    C_CI_NA_1 = 101, // 电能脉冲召唤命令
    C_RD_NA_1 = 102, // 读命令
    C_CS_NA_1 = 103, // 时钟同步命令
    C_TS_NA_1 = 104, // 测试命令
    C_RP_NA_1 = 105, // 复位进程命令
    C_CD_NA_1 = 106, // 延时获得命令
    C_TS_TA_1 = 107, // 带时标 CP56Time2a 的测试命令
    P_ME_NA_1 = 110, // 测量值参数, 归一化值
    P_ME_NB_1 = 111, // 测量值参数, 标度值
    P_ME_NC_1 = 112, // 测量值参数, 短浮点数
    P_AC_NA_1 = 113, // 参数激活
    F_FR_NA_1 = 120, // 文件已准备好
    F_SR_NA_1 = 121, // 节已准备好
    F_SC_NA_1 = 122, // 召唤目录, 选择文件, 召唤文件, 召唤节
    F_LS_NA_1 = 123, // 最后的节, 最后的段
    F_AF_NA_1 = 124, // 确认文件, 确认节
    F_SG_NA_1 = 125, // 段
    F_DR_TA_1 = 126, // 目录
    F_SC_NB_1 = 127, // 日志查询-请求存档文件
}

impl TryFrom<u8> for TypeID {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::M_SP_NA_1),
            2 => Ok(Self::M_SP_TA_1),
            3 => Ok(Self::M_DP_NA_1),
            4 => Ok(Self::M_DP_TA_1),
            5 => Ok(Self::M_ST_NA_1),
            6 => Ok(Self::M_ST_TA_1),
            7 => Ok(Self::M_BO_NA_1),
            8 => Ok(Self::M_BO_TA_1),
            9 => Ok(Self::M_ME_NA_1),
            10 => Ok(Self::M_ME_TA_1),
            11 => Ok(Self::M_ME_NB_1),
            12 => Ok(Self::M_ME_TB_1),
            13 => Ok(Self::M_ME_NC_1),
            14 => Ok(Self::M_ME_TC_1),
            15 => Ok(Self::M_IT_NA_1),
            16 => Ok(Self::M_IT_TA_1),
            17 => Ok(Self::M_EP_TA_1),
            18 => Ok(Self::M_EP_TB_1),
            19 => Ok(Self::M_EP_TC_1),
            20 => Ok(Self::M_PS_NA_1),
            21 => Ok(Self::M_ME_ND_1),
            30 => Ok(Self::M_SP_TB_1),
            31 => Ok(Self::M_DP_TB_1),
            32 => Ok(Self::M_ST_TB_1),
            33 => Ok(Self::M_BO_TB_1),
            34 => Ok(Self::M_ME_TD_1),
            35 => Ok(Self::M_ME_TE_1),
            36 => Ok(Self::M_ME_TF_1),
            37 => Ok(Self::M_IT_TB_1),
            38 => Ok(Self::M_EP_TD_1),
            39 => Ok(Self::M_EP_TE_1),
            40 => Ok(Self::M_EP_TF_1),
            41 => Ok(Self::S_IT_TC_1),
            45 => Ok(Self::C_SC_NA_1),
            46 => Ok(Self::C_DC_NA_1),
            47 => Ok(Self::C_RC_NA_1),
            48 => Ok(Self::C_SE_NA_1),
            49 => Ok(Self::C_SE_NB_1),
            50 => Ok(Self::C_SE_NC_1),
            51 => Ok(Self::C_BO_NA_1),
            52 => Ok(Self::M_IT_TA_1),
            53 => Ok(Self::M_IT_TA_1),
            54 => Ok(Self::M_IT_TA_1),
            55 => Ok(Self::M_IT_TA_1),
            56 => Ok(Self::M_IT_TA_1),
            57 => Ok(Self::M_IT_TA_1),
            58 => Ok(Self::C_SC_TA_1),
            59 => Ok(Self::C_DC_TA_1),
            60 => Ok(Self::C_RC_TA_1),
            61 => Ok(Self::C_SE_TA_1),
            62 => Ok(Self::C_SE_TB_1),
            63 => Ok(Self::C_SE_TC_1),
            64 => Ok(Self::C_BO_TA_1),
            70 => Ok(Self::M_EI_NA_1),
            81 => Ok(Self::S_CH_NA_1),
            82 => Ok(Self::S_RP_NA_1),
            83 => Ok(Self::S_AR_NA_1),
            84 => Ok(Self::S_KR_NA_1),
            85 => Ok(Self::S_KS_NA_1),
            86 => Ok(Self::S_KC_NA_1),
            87 => Ok(Self::S_ER_NA_1),
            90 => Ok(Self::S_US_NA_1),
            91 => Ok(Self::S_UQ_NA_1),
            92 => Ok(Self::S_UR_NA_1),
            93 => Ok(Self::S_UK_NA_1),
            94 => Ok(Self::S_UA_NA_1),
            95 => Ok(Self::S_UC_NA_1),
            100 => Ok(Self::C_IC_NA_1),
            101 => Ok(Self::C_CI_NA_1),
            102 => Ok(Self::C_RD_NA_1),
            103 => Ok(Self::C_CS_NA_1),
            104 => Ok(Self::C_TS_NA_1),
            105 => Ok(Self::C_RP_NA_1),
            106 => Ok(Self::C_CD_NA_1),
            107 => Ok(Self::C_TS_TA_1),
            110 => Ok(Self::P_ME_NA_1),
            111 => Ok(Self::P_ME_NB_1),
            112 => Ok(Self::P_ME_NC_1),
            113 => Ok(Self::P_AC_NA_1),
            120 => Ok(Self::F_FR_NA_1),
            121 => Ok(Self::F_SR_NA_1),
            122 => Ok(Self::F_SC_NA_1),
            123 => Ok(Self::F_LS_NA_1),
            124 => Ok(Self::F_AF_NA_1),
            125 => Ok(Self::F_SG_NA_1),
            126 => Ok(Self::F_DR_TA_1),
            127 => Ok(Self::F_SC_NB_1),
            _ => Err(anyhow!("Unknown TypeId: {}", value)),
        }
    }
}

// 信息对象地址 (IEC104)
bit_struct! {
    pub struct InfoObjAddr(u24) {
        res: u8,       // 未使用, 置0
        addr: u16,     // 有效取值 [1, 65534]
    }
}

// InfoObjAddrIrrelevant Zero means that the information object address is irrelevant.
pub const INFO_OBJ_ADDR_IRRELEVANT: u16 = 0;

impl Asdu {
    pub fn mirror(&self, cause: Cause) -> Self {
        let mut asdu = self.clone();
        asdu.identifier.cot.cause().set(cause);
        asdu
    }
}

// 尝试把 Bytes 转换为 Asdu
impl TryFrom<Bytes> for Asdu {
    type Error = anyhow::Error;

    fn try_from(bytes: Bytes) -> Result<Self> {
        // Cursor 是一个用于在字节流中进行读取和写入的结构体
        // 提供游标功能：Cursor 允许你在字节数组中移动读取位置。
        // 可以通过 Cursor 的方法（如 read_u8()、read_u16() 等）逐个读取字节，
        // 并自动管理当前读取位置。
        // 简化读取操作：使用 Cursor 可以方便地从字节流中读取不同类型的数据，
        // 而不需要手动管理字节的索引。
        // 支持多种读取方法：Cursor 实现了 Read trait，因此可以与标准库中的各种读取方法兼容，
        // 允许你使用多种方式读取数据。
        let mut rdr = Cursor::new(&bytes);
        // 尝试把 u8 转换为 TypeID
        let type_id = TypeID::try_from(rdr.read_u8()?)?;
        // 尝试把 u8 转换为 VariableStruct
        let variable_struct = VariableStruct::try_from(rdr.read_u8()?)
            .map_err(|_| anyhow!("Failed to parse variable struct"))?;
        // 尝试把 u8 转换为 CauseOfTransmission
        let cot = CauseOfTransmission::try_from(rdr.read_u8()?)
            .map_err(|_| anyhow!("Failed to parse cot struct"))?;
        // 尝试读取一个 u8
        let orig_addr = rdr.read_u8()?;
        // 尝试读取一个 u16
        let common_addr = rdr.read_u16::<byteorder::LittleEndian>()?;
        let mut bytes = bytes;

        Ok(Asdu {
            identifier: Identifier {
                type_id,
                variable_struct,
                cot,
                orig_addr,
                common_addr,
            },
            raw: bytes.split_off(IDENTIFIER_SIZE),
        })
    }
}

// 尝试把 Asdu 转换为 Bytes
impl TryInto<Bytes> for Asdu {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Bytes, Self::Error> {
        let mut buf = BytesMut::with_capacity(ASDU_SIZE_MAX);

        buf.put_u8(self.identifier.type_id as u8);
        buf.put_u8(self.identifier.variable_struct.raw());
        buf.put_u8(self.identifier.cot.raw());
        buf.put_u8(self.identifier.orig_addr);
        buf.put_u16_le(self.identifier.common_addr);
        buf.extend(self.raw);

        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_encode_asdu() -> Result<()> {
        let bytes =
            Bytes::from_static(&[0x01, 0x01, 0x06, 0x00, 0x80, 0x00, 0x00, 0x01, 0x02, 0x03]);
        let mut asdu: Asdu = bytes.clone().try_into()?;
        assert_eq!(asdu.identifier.type_id, TypeID::M_SP_NA_1);
        assert_eq!(asdu.identifier.variable_struct.number().get().value(), 0x01);
        assert_eq!(asdu.identifier.cot.cause().get(), Cause::Activation);
        assert_eq!(asdu.identifier.orig_addr, 0x00);
        assert_eq!(asdu.identifier.common_addr, 0x80);
        assert_eq!(asdu.raw, Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]));

        let raw: Bytes = asdu.try_into()?;
        assert_eq!(bytes, raw);
        Ok(())
    }
}
