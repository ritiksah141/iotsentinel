#!/usr/bin/env python3
"""
Tests for Smart Context (Rooms & Automations) — db_manager CRUD and schema.

Covers:
- smart_home_rooms CRUD: add_room, get_all_rooms, delete_room
- device_room_assignments: add_device_to_room, remove_device_from_room, get_room_devices
- smart_home_automations CRUD: save_automation, get_all_automations, delete_automation, toggle_automation
- Idempotent table creation (CREATE TABLE IF NOT EXISTS)

Run: pytest tests/test_smart_context.py -v
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from tests.conftest import create_test_schema


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _create_smart_home_schema(db_manager: DatabaseManager):
    """Add the smart-home tables needed by these tests."""
    cursor = db_manager.conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS smart_home_rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT UNIQUE NOT NULL,
            room_type TEXT,
            floor_level INTEGER,
            icon TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS device_room_assignments (
            device_ip TEXT,
            room_id INTEGER,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (device_ip, room_id),
            FOREIGN KEY (room_id) REFERENCES smart_home_rooms(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS smart_home_automations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            trigger_type TEXT NOT NULL,
            condition_text TEXT,
            action_text TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db_manager.conn.commit()


@pytest.fixture
def smart_db():
    """In-memory DB with base schema + smart-home tables."""
    db_manager = DatabaseManager(':memory:')
    create_test_schema(db_manager)
    _create_smart_home_schema(db_manager)
    yield db_manager
    db_manager.close()
    from pathlib import Path
    DatabaseManager._instances.pop(str(Path(':memory:').resolve()), None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_device(db, ip='192.168.1.50'):
    db.add_device(device_ip=ip)
    return ip


# ===========================================================================
# Room CRUD
# ===========================================================================

class TestRooms:

    def test_add_room_returns_id(self, smart_db):
        rid = smart_db.add_room('Living Room')
        assert isinstance(rid, int)
        assert rid > 0

    def test_add_duplicate_room_does_not_create_second_row(self, smart_db):
        smart_db.add_room('Kitchen')
        smart_db.add_room('Kitchen')  # duplicate — INSERT OR IGNORE
        # Only one room should exist regardless of return value
        rooms = smart_db.get_all_rooms()
        kitchen_rooms = [r for r in rooms if r['room_name'] == 'Kitchen']
        assert len(kitchen_rooms) == 1

    def test_get_all_rooms_empty(self, smart_db):
        rooms = smart_db.get_all_rooms()
        assert rooms == []

    def test_get_all_rooms_after_insert(self, smart_db):
        smart_db.add_room('Bedroom', room_type='sleeping', icon='fa-bed')
        rooms = smart_db.get_all_rooms()
        assert len(rooms) == 1
        assert rooms[0]['room_name'] == 'Bedroom'
        assert rooms[0]['room_type'] == 'sleeping'
        assert rooms[0]['icon'] == 'fa-bed'

    def test_get_all_rooms_device_count_zero(self, smart_db):
        smart_db.add_room('Office')
        rooms = smart_db.get_all_rooms()
        assert rooms[0]['device_count'] == 0

    def test_get_all_rooms_device_count_with_assignments(self, smart_db):
        rid = smart_db.add_room('Lounge')
        _add_device(smart_db, '10.0.0.1')
        _add_device(smart_db, '10.0.0.2')
        smart_db.add_device_to_room('10.0.0.1', rid)
        smart_db.add_device_to_room('10.0.0.2', rid)
        rooms = smart_db.get_all_rooms()
        assert rooms[0]['device_count'] == 2

    def test_delete_room_removes_row(self, smart_db):
        rid = smart_db.add_room('Garage')
        result = smart_db.delete_room(rid)
        assert result is True
        assert smart_db.get_all_rooms() == []

    def test_delete_room_cascades_assignments(self, smart_db):
        rid = smart_db.add_room('Attic')
        _add_device(smart_db, '10.0.0.5')
        smart_db.add_device_to_room('10.0.0.5', rid)
        smart_db.delete_room(rid)
        # Assignment must also be gone (CASCADE)
        cursor = smart_db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM device_room_assignments WHERE room_id = ?", (rid,))
        assert cursor.fetchone()[0] == 0

    def test_delete_nonexistent_room_returns_true(self, smart_db):
        # No row to delete — should still return True (no error)
        result = smart_db.delete_room(9999)
        assert result is True


# ===========================================================================
# Device ↔ Room assignments
# ===========================================================================

class TestDeviceRoomAssignments:

    def test_add_device_to_room(self, smart_db):
        rid = smart_db.add_room('Kitchen')
        _add_device(smart_db, '192.168.1.10')
        result = smart_db.add_device_to_room('192.168.1.10', rid)
        assert result is True

    def test_add_device_to_room_idempotent(self, smart_db):
        rid = smart_db.add_room('Garden')
        _add_device(smart_db)
        smart_db.add_device_to_room('192.168.1.50', rid)
        # Second insert is OR IGNORE — should not raise
        result = smart_db.add_device_to_room('192.168.1.50', rid)
        assert result is True

    def test_remove_device_from_room(self, smart_db):
        rid = smart_db.add_room('Hallway')
        _add_device(smart_db, '10.10.10.1')
        smart_db.add_device_to_room('10.10.10.1', rid)
        result = smart_db.remove_device_from_room('10.10.10.1', rid)
        assert result is True
        assert smart_db.get_room_devices(rid) == []

    def test_get_room_devices_returns_assigned_devices(self, smart_db):
        rid = smart_db.add_room('Study')
        _add_device(smart_db, '192.168.1.20')
        _add_device(smart_db, '192.168.1.21')
        smart_db.add_device_to_room('192.168.1.20', rid)
        smart_db.add_device_to_room('192.168.1.21', rid)
        devices = smart_db.get_room_devices(rid)
        ips = {d['device_ip'] for d in devices}
        assert '192.168.1.20' in ips
        assert '192.168.1.21' in ips

    def test_get_room_devices_empty_when_none_assigned(self, smart_db):
        rid = smart_db.add_room('Empty Room')
        assert smart_db.get_room_devices(rid) == []


# ===========================================================================
# Automation CRUD
# ===========================================================================

class TestAutomations:

    def test_save_automation_returns_id(self, smart_db):
        aid = smart_db.save_automation(
            name='Evening Lights',
            trigger_type='time',
            condition_text='After 8 PM',
            action_text='Turn off living room lights',
        )
        assert isinstance(aid, int)
        assert aid > 0

    def test_get_all_automations_empty(self, smart_db):
        assert smart_db.get_all_automations() == []

    def test_get_all_automations_after_save(self, smart_db):
        smart_db.save_automation(
            name='Morning Alarm',
            trigger_type='time',
            condition_text='7:00 AM weekdays',
            action_text='Turn on coffee maker',
        )
        automations = smart_db.get_all_automations()
        assert len(automations) == 1
        assert automations[0]['name'] == 'Morning Alarm'
        assert automations[0]['trigger_type'] == 'time'
        assert automations[0]['action_text'] == 'Turn on coffee maker'
        assert automations[0]['is_enabled'] == 1

    def test_save_multiple_automations(self, smart_db):
        smart_db.save_automation('Auto 1', 'time', '', 'Action 1')
        smart_db.save_automation('Auto 2', 'device', '', 'Action 2')
        smart_db.save_automation('Auto 3', 'sensor', '', 'Action 3')
        assert len(smart_db.get_all_automations()) == 3

    def test_save_automation_condition_optional(self, smart_db):
        aid = smart_db.save_automation(
            name='No Condition',
            trigger_type='device',
            condition_text=None,
            action_text='Do something',
        )
        assert aid is not None
        automations = smart_db.get_all_automations()
        assert automations[0]['condition_text'] is None

    def test_delete_automation(self, smart_db):
        aid = smart_db.save_automation('Delete Me', 'time', '', 'Action')
        result = smart_db.delete_automation(aid)
        assert result is True
        assert smart_db.get_all_automations() == []

    def test_delete_nonexistent_automation_returns_true(self, smart_db):
        result = smart_db.delete_automation(9999)
        assert result is True

    def test_toggle_automation_disable(self, smart_db):
        aid = smart_db.save_automation('Toggle Me', 'time', '', 'Action')
        result = smart_db.toggle_automation(aid, False)
        assert result is True
        automations = smart_db.get_all_automations()
        assert automations[0]['is_enabled'] == 0

    def test_toggle_automation_re_enable(self, smart_db):
        aid = smart_db.save_automation('Re-enable Me', 'time', '', 'Action')
        smart_db.toggle_automation(aid, False)
        smart_db.toggle_automation(aid, True)
        automations = smart_db.get_all_automations()
        assert automations[0]['is_enabled'] == 1

    def test_delete_one_of_many_automations(self, smart_db):
        aid1 = smart_db.save_automation('Keep', 'time', '', 'Do this')
        aid2 = smart_db.save_automation('Remove', 'device', '', 'Do that')
        smart_db.delete_automation(aid2)
        remaining = smart_db.get_all_automations()
        assert len(remaining) == 1
        assert remaining[0]['id'] == aid1


# ===========================================================================
# Schema idempotency
# ===========================================================================

class TestSchemaIdempotency:

    def test_create_smart_home_tables_twice_is_safe(self, smart_db):
        # Running the schema creation again must not raise (CREATE TABLE IF NOT EXISTS)
        _create_smart_home_schema(smart_db)
        # Tables should still work normally after a duplicate creation attempt
        rid = smart_db.add_room('Idempotent Room')
        assert rid > 0

    def test_automations_table_persists_after_multiple_creates(self, smart_db):
        smart_db.save_automation('Pre-existing', 'time', '', 'Action')
        _create_smart_home_schema(smart_db)  # second call
        automations = smart_db.get_all_automations()
        assert len(automations) == 1  # existing row preserved
