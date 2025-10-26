//! Parameter trait and types

use crate::Error;

/// Parameter trait for protocol/attack configuration
pub trait Parameter: Send + Sync {
    /// Parameter name
    fn name(&self) -> &str;

    /// Parameter description
    fn description(&self) -> &str;

    /// Parameter type
    fn value_type(&self) -> ParameterType;

    /// Default value
    fn default_value(&self) -> ParameterValue;

    /// Validate a parameter value
    fn validate(&self, value: &ParameterValue) -> Result<(), Error>;

    /// Is this parameter required?
    fn is_required(&self) -> bool {
        false
    }
}

/// Parameter type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterType {
    /// String parameter
    String,
    /// 32-bit unsigned integer
    U32,
    /// 16-bit unsigned integer
    U16,
    /// 8-bit unsigned integer
    U8,
    /// Boolean flag
    Bool,
    /// MAC address
    MacAddr,
    /// IP address
    IpAddr,
}

/// Parameter value
#[derive(Debug, Clone)]
pub enum ParameterValue {
    String(String),
    U32(u32),
    U16(u16),
    U8(u8),
    Bool(bool),
    MacAddr(crate::MacAddr),
    IpAddr(std::net::IpAddr),
}

impl ParameterValue {
    /// Get as string
    pub fn as_string(&self) -> Option<&str> {
        match self {
            ParameterValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as u32
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            ParameterValue::U32(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as u16
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            ParameterValue::U16(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as u8
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            ParameterValue::U8(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as bool
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ParameterValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as MAC address
    pub fn as_mac_addr(&self) -> Option<crate::MacAddr> {
        match self {
            ParameterValue::MacAddr(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as IP address
    pub fn as_ip_addr(&self) -> Option<std::net::IpAddr> {
        match self {
            ParameterValue::IpAddr(v) => Some(*v),
            _ => None,
        }
    }
}

impl std::fmt::Display for ParameterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterValue::String(s) => write!(f, "{}", s),
            ParameterValue::U32(v) => write!(f, "{}", v),
            ParameterValue::U16(v) => write!(f, "{}", v),
            ParameterValue::U8(v) => write!(f, "{}", v),
            ParameterValue::Bool(v) => write!(f, "{}", v),
            ParameterValue::MacAddr(v) => write!(f, "{}", v),
            ParameterValue::IpAddr(v) => write!(f, "{}", v),
        }
    }
}

/// Simple parameter implementation
pub struct SimpleParameter {
    name: String,
    description: String,
    param_type: ParameterType,
    default: ParameterValue,
    required: bool,
}

impl SimpleParameter {
    pub fn new(
        name: String,
        description: String,
        param_type: ParameterType,
        default: ParameterValue,
    ) -> Self {
        Self {
            name,
            description,
            param_type,
            default,
            required: false,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

impl Parameter for SimpleParameter {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn value_type(&self) -> ParameterType {
        self.param_type
    }

    fn default_value(&self) -> ParameterValue {
        self.default.clone()
    }

    fn validate(&self, value: &ParameterValue) -> Result<(), Error> {
        // Basic type checking
        match (self.param_type, value) {
            (ParameterType::String, ParameterValue::String(_)) => Ok(()),
            (ParameterType::U32, ParameterValue::U32(_)) => Ok(()),
            (ParameterType::U16, ParameterValue::U16(_)) => Ok(()),
            (ParameterType::U8, ParameterValue::U8(_)) => Ok(()),
            (ParameterType::Bool, ParameterValue::Bool(_)) => Ok(()),
            (ParameterType::MacAddr, ParameterValue::MacAddr(_)) => Ok(()),
            (ParameterType::IpAddr, ParameterValue::IpAddr(_)) => Ok(()),
            _ => Err(Error::invalid_parameter(
                self.name.clone(),
                "Type mismatch".to_string(),
            )),
        }
    }

    fn is_required(&self) -> bool {
        self.required
    }
}
