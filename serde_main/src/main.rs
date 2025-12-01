use bytes::{BufMut, BytesMut};
use serde_lib::{Decode, Decoder, Encode, Encoder};

// 驱动器参数Payload
#[derive(Debug, Encoder, Decoder)]
pub struct MoterDriverParam {
    foo: Foo,
    readparam_result: u8,
    max_speed_limit: u32, //电机最大转速限制（rpm）
    max_acc_speed: u32,   //电机最大加速度限制 cnt/s/ms
    max_dec_speed: u32,   //电机最大减速度限制 cnt/s/ms

    di1: u32, //隔离输入口功能配置 di1~di8
    di2: u32, //
    di3: u32, //
    di4: u32, //
    di5: u32, //
    di6: u32, //
    di7: u32, //
    di8: u32, //

    max_output_current: u32,         //最大输出电流限制
    overcurrent_time_limit: u32,     //过流时间限制ms
    speed_following_fault_time: u32, //速度跟随容错时间ms
    motors_lines: u32,               //电机增量编码器线数
    motor_poles: u32,                //电机极对数
    speed_loop_kp: u32,              //速度环kp
    speed_loop_ki: u32,              //速度环ki
    motor_positive_dir: u32,         //电机转动正方向控制
    position_loop_time: u32,         //速度跟随容错时间ms
}

#[derive(Debug, Encoder, Decoder, Clone, Copy)]
#[repr(u16)]
enum Foo {
    A = 1,
    B = 2,
}

fn main() {
    let mut bytes = BytesMut::new();
    let p = MoterDriverParam {
        foo: Foo::A,
        readparam_result: 1,
        max_speed_limit: 2,
        max_acc_speed: 3,
        max_dec_speed: 4,
        di1: 5,
        di2: 6,
        di3: 7,
        di4: 8,
        di5: 9,
        di6: 10,
        di7: 11,
        di8: 12,
        max_output_current: 13,
        overcurrent_time_limit: 14,
        speed_following_fault_time: 15,
        motors_lines: 16,
        motor_poles: 17,
        speed_loop_kp: 18,
        speed_loop_ki: 19,
        motor_positive_dir: 20,
        position_loop_time: 21,
    };
    p.encode(&mut bytes);
    println!("encode {:02X?}", bytes);

    let mut offset = 0;
    let res = MoterDriverParam::decode(bytes.as_ref(), &mut offset);

    println!("{:?}", res);
}