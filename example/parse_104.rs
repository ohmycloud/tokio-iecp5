use anyhow::Result;
use std::env;
use tokio_iecp5::asdu::TypeID;
use tokio_iecp5::inspect::inspect_frames;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("用法: parse_104 <16进制报文字符串>");
        println!("示例: parse_104 680407000000");
        println!("示例: parse_104 68 04 07 00 00 00");
        println!("示例: parse_104 '[68] [04] [07] [00] [00] [00]'");
        return Ok(());
    }
    let hex_input = args[1..].join("");
    for apdu in inspect_frames(&hex_input)? {
        println!("解析成功: {:#?}", apdu);
        // 判断是否为I帧
        if apdu.apci.ctrl1 & 0x01 == 0 {
            if let Some(mut asdu) = apdu.asdu {
                match asdu.identifier.type_id {
                    TypeID::M_SP_NA_1 | TypeID::M_SP_TA_1 | TypeID::M_SP_TB_1 => {
                        match asdu.get_single_point() {
                            Ok(points) => println!("单点信息: {:#?}", points),
                            Err(e) => println!("单点信息解析失败: {e}"),
                        }
                    }
                    TypeID::M_DP_NA_1 | TypeID::M_DP_TA_1 | TypeID::M_DP_TB_1 => {
                        match asdu.get_double_point() {
                            Ok(points) => println!("双点信息: {:#?}", points),
                            Err(e) => println!("双点信息解析失败: {e}"),
                        }
                    }
                    TypeID::M_ME_NA_1
                    | TypeID::M_ME_TA_1
                    | TypeID::M_ME_TD_1
                    | TypeID::M_ME_ND_1 => match asdu.get_measured_value_normal() {
                        Ok(vals) => println!("测量值(规一化): {:#?}", vals),
                        Err(e) => println!("测量值(规一化)解析失败: {e}"),
                    },
                    TypeID::M_ME_NB_1 | TypeID::M_ME_TB_1 | TypeID::M_ME_TE_1 => {
                        match asdu.get_measured_value_scaled() {
                            Ok(vals) => println!("测量值(标度化): {:#?}", vals),
                            Err(e) => println!("测量值(标度化)解析失败: {e}"),
                        }
                    }
                    TypeID::M_ME_NC_1 | TypeID::M_ME_TC_1 | TypeID::M_ME_TF_1 => {
                        match asdu.get_measured_value_float() {
                            Ok(vals) => println!("测量值(浮点): {:#?}", vals),
                            Err(e) => println!("测量值(浮点)解析失败: {e}"),
                        }
                    }
                    TypeID::M_IT_NA_1 | TypeID::M_IT_TA_1 | TypeID::M_IT_TB_1 => {
                        match asdu.get_integrated_totals() {
                            Ok(vals) => println!("累计量: {:#?}", vals),
                            Err(e) => println!("累计量解析失败: {e}"),
                        }
                    }
                    TypeID::C_SC_NA_1 | TypeID::C_SC_TA_1 => match asdu.get_single_cmd() {
                        Ok(cmd) => println!("单命令: {:#?}", cmd),
                        Err(e) => println!("单命令解析失败: {e}"),
                    },
                    TypeID::C_DC_NA_1 | TypeID::C_DC_TA_1 => match asdu.get_double_cmd() {
                        Ok(cmd) => println!("双命令: {:#?}", cmd),
                        Err(e) => println!("双命令解析失败: {e}"),
                    },
                    TypeID::C_IC_NA_1 => match asdu.get_interrogation_cmd() {
                        Ok(val) => println!("总召唤: {:#?}", val),
                        Err(e) => println!("总召唤解析失败: {e}"),
                    },
                    TypeID::C_CI_NA_1 => match asdu.get_counter_interrogation_cmd() {
                        Ok(val) => println!("计数召唤: {:#?}", val),
                        Err(e) => println!("计数召唤解析失败: {e}"),
                    },
                    TypeID::C_RP_NA_1 => match asdu.get_reset_process_cmd() {
                        Ok(val) => println!("复位进程命令: {:#?}", val),
                        Err(e) => println!("复位进程命令解析失败: {e}"),
                    },
                    TypeID::C_SE_NA_1 | TypeID::C_SE_TA_1 => match asdu.get_setpoint_normal_cmd() {
                        Ok(cmd) => println!("设定命令(规一化): {:#?}", cmd),
                        Err(e) => println!("设定命令(规一化)解析失败: {e}"),
                    },
                    TypeID::C_SE_NB_1 | TypeID::C_SE_TB_1 => match asdu.get_setpoint_scaled_cmd() {
                        Ok(cmd) => println!("设定命令(标度化): {:#?}", cmd),
                        Err(e) => println!("设定命令(标度化)解析失败: {e}"),
                    },
                    TypeID::C_SE_NC_1 | TypeID::C_SE_TC_1 => match asdu.get_setpoint_float_cmd() {
                        Ok(cmd) => println!(
                            "设定命令(浮点): ioa={:?}, r={}, qos={:?}, time={:?}",
                            cmd.ioa, cmd.r, cmd.qos, cmd.time
                        ),
                        Err(e) => println!("设定命令(浮点)解析失败: {e}"),
                    },
                    TypeID::C_BO_NA_1 | TypeID::C_BO_TA_1 => match asdu.get_bits_string32_cmd() {
                        Ok(cmd) => println!(
                            "比特串命令: ioa={:?}, bcr={}, time={:?}",
                            cmd.ioa, cmd.bcr, cmd.time
                        ),
                        Err(e) => println!("比特串命令解析失败: {e}"),
                    },
                    TypeID::M_EI_NA_1 => match asdu.get_end_of_initialization() {
                        Ok(val) => println!("初始化结束: {:#?}", val),
                        Err(e) => println!("初始化结束解析失败: {e}"),
                    },
                    _ => {
                        println!("暂不支持的TypeID: {:?}", asdu.identifier.type_id);
                        println!("原始raw: {:?}", asdu.raw);
                    }
                }
            } else {
                println!("I帧但未携带ASDU");
            }
        }
    }
    Ok(())
}
