// Fuzz target: SMBIOS dump parser (base/smbios_parser.cc).
//
// The host sends its raw SMBIOS dump to the client in the system-info reply, and the client and
// host both walk it with SmbiosTableEnumerator + the per-type table wrappers (see
// host/workers/sys_info_worker.cc). The harness feeds the input as the dump, walks every table and
// calls every getter of the wrapper that matches the table type, as the consumers do.
#include <QByteArray>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "base/smbios.h"
#include "base/smbios_parser.h"

namespace {

volatile size_t g_sink;

template <typename T> void sink(const T& v) { g_sink += sizeof(v); }
void sink(const std::string& v) { g_sink += v.size(); }
void sink(const QByteArray& v) { g_sink += static_cast<size_t>(v.size()); }
void sink(const std::vector<std::string>& v) { for (const auto& s : v) g_sink += s.size(); }
void sink(const quint8* p) { g_sink += (p != nullptr); }

void visit(const SmbiosTable* table)
{
    switch (table->type)
    {
        case SMBIOS_TABLE_TYPE_BIOS:
        {
            SmbiosBios t(table);
            if (!t.isValid()) break;
            sink(t.vendor());
            sink(t.version());
            sink(t.releaseDate());
            sink(t.address());
            sink(t.romSize());
            sink(t.revision());
            sink(t.firmwareRevision());
            sink(t.characteristics());
        }
        break;
        case SMBIOS_TABLE_TYPE_SYSTEM:
        {
            SmbiosSystem t(table);
            if (!t.isValid()) break;
            sink(t.uuid());
        }
        break;
        case SMBIOS_TABLE_TYPE_BASEBOARD:
        {
            SmbiosBaseboard t(table);
            if (!t.isValid()) break;
            sink(t.manufacturer());
            sink(t.product());
            sink(t.version());
            sink(t.serialNumber());
            sink(t.assetTag());
            sink(t.location());
            sink(t.type());
            sink(t.isHostingBoard());
            sink(t.requiresDaughterBoard());
            sink(t.isRemovable());
            sink(t.isReplaceable());
            sink(t.isHotSwappable());
        }
        break;
        case SMBIOS_TABLE_TYPE_CHASSIS:
        {
            SmbiosChassis t(table);
            if (!t.isValid()) break;
            sink(t.manufacturer());
            sink(t.version());
            sink(t.serialNumber());
            sink(t.assetTag());
            sink(t.skuNumber());
            sink(t.type());
            sink(t.isLockPresent());
            sink(t.bootUpState());
            sink(t.powerSupplyState());
            sink(t.thermalState());
            sink(t.securityStatus());
            sink(t.height());
            sink(t.powerCords());
        }
        break;
        case SMBIOS_TABLE_TYPE_PROCESSOR:
        {
            SmbiosProcessor t(table);
            if (!t.isValid()) break;
            sink(t.isPopulated());
            sink(t.manufacturer());
            sink(t.version());
            sink(t.serialNumber());
            sink(t.assetTag());
            sink(t.partNumber());
            sink(t.socketDesignation());
            sink(t.type());
            sink(t.family());
            sink(t.status());
            sink(t.upgrade());
            sink(t.socketType());
            sink(t.id());
            sink(t.voltage());
            sink(t.externalClock());
            sink(t.maxSpeed());
            sink(t.currentSpeed());
            sink(t.coreCount());
            sink(t.coreEnabled());
            sink(t.threadCount());
            sink(t.threadEnabled());
            sink(t.l1CacheHandle());
            sink(t.l2CacheHandle());
            sink(t.l3CacheHandle());
            sink(t.is64Bit());
            sink(t.isMultiCore());
            sink(t.isHardwareThread());
            sink(t.isExecuteProtection());
            sink(t.isEnhancedVirtualization());
            sink(t.isPowerPerformanceControl());
        }
        break;
        case SMBIOS_TABLE_TYPE_CACHE:
        {
            SmbiosCache t(table);
            if (!t.isValid()) break;
            sink(t.isEnabled());
            sink(t.isSocketed());
            sink(t.designation());
            sink(t.location());
            sink(t.mode());
            sink(t.type());
            sink(t.errorCorrectionType());
            sink(t.associativity());
            sink(t.currentSramType());
            sink(t.level());
            sink(t.maxSize());
            sink(t.currentSize());
            sink(t.speed());
            sink(t.supportsNonBurst());
            sink(t.supportsBurst());
            sink(t.supportsPipelineBurst());
            sink(t.supportsSynchronous());
            sink(t.supportsAsynchronous());
        }
        break;
        case SMBIOS_TABLE_TYPE_PORT_CONNECTOR:
        {
            SmbiosPortConnector t(table);
            if (!t.isValid()) break;
            sink(t.internalDesignator());
            sink(t.internalConnectorType());
            sink(t.externalDesignator());
            sink(t.externalConnectorType());
            sink(t.type());
        }
        break;
        case SMBIOS_TABLE_TYPE_SYSTEM_SLOT:
        {
            SmbiosSystemSlot t(table);
            if (!t.isValid()) break;
            sink(t.designation());
            sink(t.type());
            sink(t.dataBusWidth());
            sink(t.usage());
            sink(t.length());
            sink(t.id());
            sink(t.hasBusAddress());
            sink(t.segmentGroupNumber());
            sink(t.busNumber());
            sink(t.deviceNumber());
            sink(t.functionNumber());
            sink(t.provides5Volts());
            sink(t.provides3Volts());
            sink(t.isShared());
            sink(t.supportsPme());
            sink(t.supportsHotPlug());
            sink(t.supportsSmbus());
            sink(t.supportsBifurcation());
        }
        break;
        case SMBIOS_TABLE_TYPE_ONBOARD_DEVICE:
        {
            SmbiosOnBoardDevices t(table);
            if (!t.isValid()) break;
            sink(t.count());
            for (int i = 0; i < static_cast<int>(t.count()); ++i) {
                sink(t.description(i));
                sink(t.type(i));
                sink(t.isEnabled(i));
            }
        }
        break;
        case SMBIOS_TABLE_TYPE_OEM_STRINGS:
        case SMBIOS_TABLE_TYPE_CONFIGURATION_OPTION:
        {
            SmbiosStringList t(table);
            if (!t.isValid()) break;
            sink(t.count());
            for (int i = 0; i < static_cast<int>(t.count()); ++i) {
                sink(t.string(i));
            }
        }
        break;
        case SMBIOS_TABLE_TYPE_MEMORY_ARRAY:
        {
            SmbiosMemoryArray t(table);
            if (!t.isValid()) break;
            sink(t.location());
            sink(t.use());
            sink(t.errorCorrection());
            sink(t.maxCapacity());
            sink(t.deviceCount());
        }
        break;
        case SMBIOS_TABLE_TYPE_MEMORY_DEVICE:
        {
            SmbiosMemoryDevice t(table);
            if (!t.isValid()) break;
            sink(t.isPresent());
            sink(t.location());
            sink(t.bankLocator());
            sink(t.manufacturer());
            sink(t.serialNumber());
            sink(t.assetTag());
            sink(t.size());
            sink(t.type());
            sink(t.formFactor());
            sink(t.technology());
            sink(t.partNumber());
            sink(t.firmwareVersion());
            sink(t.speed());
            sink(t.configuredSpeed());
            sink(t.totalWidth());
            sink(t.dataWidth());
            sink(t.rank());
            sink(t.minVoltage());
            sink(t.maxVoltage());
            sink(t.configuredVoltage());
            sink(t.nonVolatileSize());
            sink(t.volatileSize());
            sink(t.cacheSize());
            sink(t.logicalSize());
            sink(t.typeDetail());
            sink(t.arrayHandle());
        }
        break;
        case SMBIOS_TABLE_TYPE_MEMORY_ERROR:
        {
            SmbiosMemoryError t(table);
            if (!t.isValid()) break;
            sink(t.type());
            sink(t.granularity());
            sink(t.operation());
            sink(t.vendorSyndrome());
            sink(t.arrayErrorAddress());
            sink(t.deviceErrorAddress());
            sink(t.errorResolution());
        }
        break;
        case SMBIOS_TABLE_TYPE_MEMORY_ARRAY_ADDRESS:
        {
            SmbiosMemoryArrayAddress t(table);
            if (!t.isValid()) break;
            sink(t.startAddress());
            sink(t.endAddress());
            sink(t.size());
            sink(t.arrayHandle());
            sink(t.partitionWidth());
        }
        break;
        case SMBIOS_TABLE_TYPE_MEMORY_DEVICE_ADDR:
        {
            SmbiosMemoryDeviceAddress t(table);
            if (!t.isValid()) break;
            sink(t.startAddress());
            sink(t.endAddress());
            sink(t.size());
            sink(t.deviceHandle());
            sink(t.arrayAddressHandle());
            sink(t.rowPosition());
            sink(t.interleavePosition());
            sink(t.interleaveDepth());
        }
        break;
        case SMBIOS_TABLE_TYPE_POINTING_DEVICE:
        {
            SmbiosPointingDevice t(table);
            if (!t.isValid()) break;
            sink(t.type());
            sink(t.interfaceType());
            sink(t.buttonCount());
        }
        break;
        case SMBIOS_TABLE_TYPE_PORTABLE_BATTERY:
        {
            SmbiosPortableBattery t(table);
            if (!t.isValid()) break;
            sink(t.location());
            sink(t.manufacturer());
            sink(t.manufactureDate());
            sink(t.serialNumber());
            sink(t.deviceName());
            sink(t.chemistry());
            sink(t.sbdsVersion());
            sink(t.designCapacity());
            sink(t.designVoltage());
            sink(t.maxError());
        }
        break;
        case SMBIOS_TABLE_TYPE_VOLTAGE_PROBE:
        case SMBIOS_TABLE_TYPE_TEMPERATURE_PROBE:
        case SMBIOS_TABLE_TYPE_CURRENT_PROBE:
        {
            SmbiosProbe t(table);
            if (!t.isValid()) break;
            sink(t.description());
            sink(t.location());
            sink(t.status());
            sink(t.maxValue());
            sink(t.minValue());
            sink(t.nominalValue());
            sink(t.tolerance());
            sink(t.resolution());
            sink(t.accuracy());
        }
        break;
        case SMBIOS_TABLE_TYPE_COOLING_DEVICE:
        {
            SmbiosCoolingDevice t(table);
            if (!t.isValid()) break;
            sink(t.description());
            sink(t.type());
            sink(t.status());
            sink(t.unitGroup());
            sink(t.nominalSpeed());
        }
        break;
        case SMBIOS_TABLE_TYPE_SYSTEM_BOOT:
        {
            SmbiosSystemBoot t(table);
            if (!t.isValid()) break;
            sink(t.status());
        }
        break;
        case SMBIOS_TABLE_TYPE_POWER_SUPPLY:
        {
            SmbiosPowerSupply t(table);
            if (!t.isValid()) break;
            sink(t.isPresent());
            sink(t.isUnplugged());
            sink(t.isHotReplaceable());
            sink(t.unitGroup());
            sink(t.location());
            sink(t.deviceName());
            sink(t.manufacturer());
            sink(t.serialNumber());
            sink(t.assetTag());
            sink(t.modelPartNumber());
            sink(t.revisionLevel());
            sink(t.type());
            sink(t.status());
            sink(t.inputVoltageRangeSwitching());
            sink(t.maxPowerCapacity());
        }
        break;
        case SMBIOS_TABLE_TYPE_ADDITIONAL_INFO:
        {
            SmbiosAdditionalInfo t(table);
            if (!t.isValid()) break;
            sink(t.count());
            for (int i = 0; i < static_cast<int>(t.count()); ++i) {
                sink(t.referencedHandle(i));
                sink(t.referencedOffset(i));
                sink(t.string(i));
                sink(t.value(i));
            }
        }
        break;
        case SMBIOS_TABLE_TYPE_ONBOARD_DEVICE_EXT:
        {
            SmbiosOnBoardDeviceExt t(table);
            if (!t.isValid()) break;
            sink(t.isEnabled());
            sink(t.designation());
            sink(t.type());
            sink(t.typeInstance());
            sink(t.hasBusAddress());
            sink(t.segmentGroupNumber());
            sink(t.busNumber());
            sink(t.deviceNumber());
            sink(t.functionNumber());
        }
        break;
        case SMBIOS_TABLE_TYPE_TPM_DEVICE:
        {
            SmbiosTpmDevice t(table);
            if (!t.isValid()) break;
            sink(t.vendorId());
            sink(t.specVersion());
            sink(t.firmwareVersion());
            sink(t.description());
            sink(t.isFamilyConfigurableByFirmware());
            sink(t.isFamilyConfigurableBySoftware());
            sink(t.isFamilyConfigurableByOem());
        }
        break;
        case SMBIOS_TABLE_TYPE_FIRMWARE_INVENTORY:
        {
            SmbiosFirmwareInventory t(table);
            if (!t.isValid()) break;
            sink(t.name());
            sink(t.version());
            sink(t.versionFormat());
            sink(t.id());
            sink(t.idFormat());
            sink(t.releaseDate());
            sink(t.manufacturer());
            sink(t.lowestVersion());
            sink(t.state());
            sink(t.isUpdatable());
            sink(t.isWriteProtected());
            sink(t.imageSize());
            sink(t.componentCount());
            for (int i = 0; i < static_cast<int>(t.componentCount()); ++i) {
                sink(t.componentHandle(i));
            }
        }
        break;
        case SMBIOS_TABLE_TYPE_PROCESSOR_INFO_EXT:
        {
            SmbiosProcessorInfoExt t(table);
            if (!t.isValid()) break;
            sink(t.processorHandle());
            sink(t.architecture());
        }
        break;
        default:
            break;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const QByteArray dump(reinterpret_cast<const char*>(data), static_cast<qsizetype>(size));
    SmbiosTableEnumerator enumerator(dump);
    sink(enumerator.majorVersion());
    sink(enumerator.minorVersion());
    sink(enumerator.length());
    for (; !enumerator.isAtEnd(); enumerator.advance())
        visit(enumerator.table());
    return 0;
}
