use std::env;

pub fn enable_test() -> bool {
    let enable = match env::var("TEST_ENABLE") {
        Ok(val) => str::to_lowercase(&*val) == "true",
        Err(_e) => false,
    };
    return enable
}

pub fn test_vpcid() -> String {
    return env::var("MOCK_VPCID").unwrap();
}

pub fn test_vip() -> String {
    return env::var("MOCK_VIP").unwrap();
}

