import { faker } from '@faker-js/faker';

export interface UserEntity {
  upn: string;
  name: string;
  ip: string;
  country: string;
  device: string;
}

export function generateBenignUsers(count: number, seed: number): UserEntity[] {
  faker.seed(seed);
  const users: UserEntity[] = [];

  const internalSubnet = '198.51.100.';

  for (let i = 1; i <= count; i++) {
    const pad = String(i).padStart(3, '0');
    const firstName = faker.person.firstName();
    const lastName = faker.person.lastName();
    users.push({
      upn: `user${pad}@contoso.test`,
      name: `${firstName} ${lastName}`,
      ip: `${internalSubnet}${10 + (i % 240)}`,
      country: i % 20 === 0 ? 'GB' : 'US',
      device: `WORKSTATION-${pad}`
    });
  }

  return users;
}

export function generateBaselineSigninLogs(
  users: UserEntity[],
  startTime: Date,
  durationHours: number
): Record<string, any>[] {
  const events: Record<string, any>[] = [];

  for (const user of users) {
    // Normal successful logins
    const loginCount = faker.number.int({ min: 2, max: 5 });
    for (let k = 0; k < loginCount; k++) {
      const offsetMinutes = faker.number.int({ min: 10, max: durationHours * 60 - 10 });
      const eventTime = new Date(startTime.getTime() + offsetMinutes * 60 * 1000).toISOString();

      events.push({
        TimeGenerated: eventTime,
        UserPrincipalName: user.upn,
        UserId: faker.string.uuid(),
        IPAddress: user.ip,
        ResultType: "0",
        ResultDescription: "Success",
        AppDisplayName: faker.helpers.arrayElement(["Microsoft Teams", "Office 365 Exchange Online", "SharePoint Online"]),
        AppId: faker.string.uuid(),
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        Location: user.country,
        LocationDetails: { countryOrRegion: user.country, city: user.country === 'GB' ? 'London' : 'Seattle' },
        DeviceDetail: { deviceId: faker.string.uuid(), operatingSystem: "Windows 11" },
        ConditionalAccessStatus: "success"
      });
    }

    // Occasional benign password typo (1 typo per 5 users, never multiple accounts)
    if (faker.number.int({ min: 1, max: 5 }) === 1) {
      const offsetMinutes = faker.number.int({ min: 5, max: durationHours * 60 - 15 });
      const typoTime = new Date(startTime.getTime() + offsetMinutes * 60 * 1000).toISOString();

      events.push({
        TimeGenerated: typoTime,
        UserPrincipalName: user.upn,
        UserId: faker.string.uuid(),
        IPAddress: user.ip,
        ResultType: "50126",
        ResultDescription: "Error validating credentials due to invalid username or password.",
        AppDisplayName: "Office 365 Exchange Online",
        AppId: faker.string.uuid(),
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        Location: user.country,
        LocationDetails: { countryOrRegion: user.country, city: "Seattle" },
        DeviceDetail: { deviceId: faker.string.uuid(), operatingSystem: "Windows 11" },
        ConditionalAccessStatus: "failure"
      });
    }
  }

  return events;
}

export function generateBaselineProcessEvents(
  users: UserEntity[],
  startTime: Date,
  durationHours: number
): Record<string, any>[] {
  const events: Record<string, any>[] = [];

  for (const user of users) {
    const eventCount = faker.number.int({ min: 3, max: 8 });
    for (let k = 0; k < eventCount; k++) {
      const offsetMinutes = faker.number.int({ min: 5, max: durationHours * 60 - 5 });
      const eventTime = new Date(startTime.getTime() + offsetMinutes * 60 * 1000).toISOString();

      const benignApp = faker.helpers.arrayElement([
        { exe: "msedge.exe", path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", cmd: "msedge.exe --profile-directory=Default", parent: "explorer.exe" },
        { exe: "OUTLOOK.EXE", path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", cmd: "OUTLOOK.EXE /recycle", parent: "explorer.exe" },
        { exe: "teams.exe", path: "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", cmd: "teams.exe --process-start-args", parent: "explorer.exe" },
        { exe: "notepad.exe", path: "C:\\Windows\\System32\\notepad.exe", cmd: "notepad.exe", parent: "explorer.exe" }
      ]);

      events.push({
        Timestamp: eventTime,
        DeviceId: faker.string.uuid(),
        DeviceName: `${user.device}.corp.contoso.test`,
        ActionType: "ProcessCreated",
        FileName: benignApp.exe,
        FolderPath: benignApp.path,
        SHA256: faker.string.hexadecimal({ length: 64, casing: 'lower', prefix: '' }),
        ProcessCommandLine: benignApp.cmd,
        ProcessIntegrityLevel: "Medium",
        ProcessTokenElevation: "TokenElevationTypeLimited",
        AccountName: user.name.toLowerCase().replace(' ', '.'),
        AccountDomain: "CONTOSO",
        InitiatingProcessFileName: benignApp.parent,
        InitiatingProcessCommandLine: benignApp.parent,
        InitiatingProcessParentFileName: "wininit.exe",
        InitiatingProcessAccountName: user.name.toLowerCase().replace(' ', '.')
      });
    }
  }

  return events;
}

export function generateBaselineCloudEvents(
  users: UserEntity[],
  startTime: Date,
  durationHours: number
): Record<string, any>[] {
  const events: Record<string, any>[] = [];

  for (const user of users) {
    // Normal routine file download (1-3 files over a workday)
    const downloadCount = faker.number.int({ min: 1, max: 3 });
    for (let k = 0; k < downloadCount; k++) {
      const offsetMinutes = faker.number.int({ min: 15, max: durationHours * 60 - 15 });
      const eventTime = new Date(startTime.getTime() + offsetMinutes * 60 * 1000).toISOString();

      events.push({
        Timestamp: eventTime,
        ActionType: "FileDownloaded",
        Application: "Microsoft SharePoint Online",
        AccountDisplayName: user.name,
        AccountId: user.upn,
        AccountType: "Regular",
        IPAddress: user.ip,
        CountryCode: user.country,
        City: "Seattle",
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ActivityType: "FileDownloaded",
        ActivityObjects: [`https://contoso.sharepoint.test/sites/general/Shared Documents/Report_${k}.docx`],
        RawEventData: { ClientIP: user.ip, Operation: "FileDownloaded" }
      });
    }
  }

  return events;
}

